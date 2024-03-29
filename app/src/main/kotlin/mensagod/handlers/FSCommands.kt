package mensagod.handlers

import keznacl.UnsupportedAlgorithmException
import keznacl.getType
import keznacl.onFalse
import keznacl.toHash
import libkeycard.RandomID
import libmensago.ClientRequest
import libmensago.MServerPath
import libmensago.ServerResponse
import mensagod.*
import mensagod.auth.*
import mensagod.dbcmds.*
import java.time.Instant
import java.util.*

// COPY(SourceFile,DestDir)
fun commandCopy(state: ClientSession) {
    val schema = Schemas.copy
    if (!state.requireLogin(schema)) return
    val sourceFilePath = schema.getPath("SourceFile", state.message.data)!!
    val destPath = schema.getPath("DestDir", state.message.data)!!
    if (!sourceFilePath.isFile()) {
        state.quickResponse(404, "BAD REQUEST", "SourceFile must be a path to a file")
        return
    }
    if (!destPath.isDir()) {
        state.quickResponse(
            404, "BAD REQUEST",
            "DestDir must be a path to a directory"
        )
        return
    }

    val lfs = LocalFS.get()
    checkDirectoryAccess(
        state,
        lfs.entry(sourceFilePath.parent()!!),
        AuthAction.Access
    ).onFalse { return }
    checkDirectoryAccess(state, lfs.entry(destPath), AuthAction.Create).onFalse { return }
    val fileSize = sourceFilePath.size()
    checkQuota(state, fileSize)?.onFalse { return } ?: return

    var destFilePath = MServerPath()
    lfs.withLock(sourceFilePath) {
        sourceFilePath.toHandle().copyTo(destPath).onSuccess { destFilePath = it }.exceptionOrNull()
    }?.let {
        state.internalError(
            "Error copying file $sourceFilePath to $destPath: $it",
            "Internal error copying file"
        )
        return
    }

    withDB { db ->
        addSyncRecord(
            db, state.wid!!, SyncRecord(
                RandomID.generate(),
                UpdateType.Create,
                destFilePath.toString(),
                Instant.now().epochSecond.toString(),
                state.devid!!
            )
        )?.let {
            state.internalError(
                "commandCopy: failed to add update entry for $destFilePath: $it",
                "Error adding update entry for created file"
            )
            db.disconnect()
            return
        }
    }.onFalse { return }

    ServerResponse(200, "OK").attach("NewName", destFilePath.basename())
        .sendCatching(state.conn, "Error sending new name from COPY")
}

// DELETE(FileCount,File0...)
fun commandDelete(state: ClientSession) {
    val schema = Schemas.delete
    if (!state.requireLogin(schema)) return

    val fileCount = schema.getInteger("FileCount", state.message.data)!!
    for (i in 0 until fileCount) {
        if (!state.message.data.containsKey("File$i")) {
            state.quickResponse(400, "BAD REQUEST", "File list missing index $i")
            return
        }
        val rawPath = "${state.currentPath} ${state.message.data["File$i"]}"
        val path = MServerPath.fromString(rawPath)
            ?: run {
                state.internalError(
                    "Invalid path '$rawPath' in DELETE",
                    "Invalid path error for DELETE"
                )
                return
            }
        if (path.isDir()) {
            state.quickResponse(400, "BAD REQUEST", "$path is not a file")
            return
        }
        path.toHandle().exists().getOrElse {
            state.internalError(
                "Error checking file $path existence: $it",
                "Server error checking for file $path"
            )
            return
        }.onFalse {
            state.quickResponse(404, "RESOURCE NOT FOUND", path.toString())
            return
        }
    }

    val lfs = LocalFS.get()
    checkDirectoryAccess(state, lfs.entry(state.currentPath), AuthAction.Delete).onFalse { return }

    val db = state.dbConnect() ?: return
    for (i in 0 until fileCount) {
        val fileHandle = MServerPath("${state.currentPath} ${state.message.data["File$i"]}")
            .toHandle()
        fileHandle.delete()?.let {
            state.internalError(
                "Failed to delete ${fileHandle.path}: $it",
                "Error deleting file"
            )
            db.disconnect()
            return
        }

        addSyncRecord(
            db, state.wid!!, SyncRecord(
                RandomID.generate(),
                UpdateType.Delete,
                fileHandle.path.toString(),
                Instant.now().epochSecond.toString(),
                state.devid!!
            )
        )?.let {
            state.internalError(
                "commandDelete: failed to add update entry for ${fileHandle.path}: $it",
                "Error adding update entry for deleted file"
            )
            db.disconnect()
            return
        }
    }
    db.disconnect()
    state.quickResponse(200, "OK")
}

// DOWNLOAD(Path,Offset=0)
fun commandDownload(state: ClientSession) {
    val schema = Schemas.download
    if (!state.requireLogin(schema)) return
    val path = schema.getPath("Path", state.message.data)!!
    val lfs = LocalFS.get()
    val handle = lfs.entry(path)
    val offset = schema.getLong("Offset", state.message.data) ?: 0L

    // The FileTarget class verifies that the path is, indeed, pointing to a file
    val fileTarget = FileTarget.fromPath(path) ?: run {
        state.quickResponse(400, "BAD REQUEST", "Path must be for a file")
        return
    }
    fileTarget.isAuthorized(WIDActor(state.wid!!), AuthAction.Read)
        .getOrElse {
            state.internalError(
                "commandDownload: Auth check error: $it",
                "Error checking authorization"
            )
            return
        }.onFalse {
            state.quickResponse(403, "FORBIDDEN")
            return
        }

    handle.exists().getOrElse {
        state.internalError(
            "commandDownload: Error checking existence of $path: $it",
            "Error checking path existence"
        )
        return
    }.onFalse {
        state.quickResponse(404, "RESOUCE NOT FOUND")
        return
    }

    val fileSize = handle.size().getOrElse {
        state.internalError(
            "commandDownload: Error getting size of $path: $it",
            "Error getting file size"
        )
        return
    }
    if (offset < 0 || offset > fileSize) {
        state.quickResponse(400, "BAD REQUEST", "Offset out of range")
        return
    }

    ServerResponse(
        100, "CONTINUE", "",
        mutableMapOf("Size" to fileSize.toString())
    ).sendCatching(
        state.conn,
        "commandDownload: Error sending continue message for wid ${state.wid!!}"
    ).onFalse { return }

    val req = ClientRequest.receive(state.conn.getInputStream()).getOrElse {
        logDebug("commandDownload: error receiving client continue request: $it")
        return
    }
    if (req.action == "CANCEL") return

    if (req.action != "DOWNLOAD" || !req.hasField("Size")) {
        state.quickResponse(400, "BAD REQUEST", "Session mismatch")
        return
    }

    lfs.withLock(path) { state.sendFileData(path, fileSize, offset) }?.let {
        logDebug("commandDownload: sendFileData error for ${state.wid}: $it")
    }
}

// EXISTS(Path)
fun commandExists(state: ClientSession) {
    val schema = Schemas.exists
    if (!state.requireLogin(schema)) return

    val entry = schema.getPath("Path", state.message.data)!!.toHandle()

    entry.exists().getOrElse {
        state.internalError(
            "Error checking existence of ${entry.path}: $it",
            "Error checking existence of path"
        )
        return
    }.onFalse {
        state.quickResponse(404, "NOT FOUND")
        return
    }

    state.quickResponse(200, "OK")
}

// GETQUOTAINFO(Workspace=null)
fun commandGetQuotaInfo(state: ClientSession) {
    val schema = Schemas.getQuotaInfo
    if (!state.requireLogin(schema)) return
    val targetWID = schema.getRandomID("Workspace-ID", state.message.data) ?: state.wid!!
    checkWorkspaceAccess(state, targetWID, AuthAction.GetQuota).onFalse { return }
    val qinfo = withDBResult { db ->
        getQuotaInfo(db, targetWID).getOrElse {
            state.internalError(
                "Error getting quota info for $targetWID: $it",
                "Server error getting disk quota info"
            )
            db.disconnect()
            return
        }
    }.getOrElse { state.unavailableError(); return }

    ServerResponse(200, "OK")
        .attach("DiskUsage", qinfo.first)
        .attach("QuotaSize", qinfo.second)
        .sendCatching(state.conn, "Error sending quota info to ${state.wid}")
}

// LIST(Path=null)
fun commandList(state: ClientSession) {
    val schema = Schemas.list
    if (!state.requireLogin(schema)) return

    val entry = (schema.getPath("Path", state.message.data) ?: state.currentPath).toHandle()
    val unixtime = schema.getUnixTime("Time", state.message.data)
    checkDirectoryAccess(state, entry, AuthAction.Access).onFalse { return }

    val fileList = entry.getFile().listFiles()?.filter { it.isFile }?.map { it.name }?.sorted()
    if (fileList == null) {
        state.internalError(
            "Null file list received for ${entry.path}",
            "Server error: null file list received"
        )
    }
    val response = ServerResponse(200, "OK")
    if (unixtime != null) {
        val filteredList = fileList!!.filter {
            val parts = it.split(".")
            if (parts.size != 3) return@filter false
            val time = runCatching { parts[0].toLong() }.getOrElse { return@filter false }
            time > unixtime
        }
        response.attach("FileCount", filteredList.size)
        if (filteredList.isNotEmpty())
            response.attach("Files", filteredList.joinToString(","))
    } else {
        response.attach("FileCount", fileList!!.size)
        if (fileList.isNotEmpty())
            response.attach("Files", fileList.joinToString(","))
    }


    response.sendCatching(state.conn, "Error sending LIST results")
}

// LISTDIRS(Path=null)
fun commandListDirs(state: ClientSession) {
    val schema = Schemas.listDirs
    if (!state.requireLogin(schema)) return

    val entry = (schema.getPath("Path", state.message.data) ?: state.currentPath).toHandle()
    checkDirectoryAccess(state, entry, AuthAction.Access).onFalse { return }

    val dirList = entry.getFile().listFiles()?.filter { it.isDirectory }?.map { it.name }?.sorted()
    if (dirList == null) {
        state.internalError(
            "Null directory list received for ${entry.path}",
            "Server error: null directory list received"
        )
    }
    val response = ServerResponse(200, "OK")
        .attach("DirectoryCount", dirList!!.size)
    if (dirList.isNotEmpty())
        response.attach("Directories", dirList.joinToString(","))
    response.sendCatching(state.conn, "Error sending LISTDIRS results")
}

// MKDIR(Path, ClientPath)
fun commandMkDir(state: ClientSession) {
    val schema = Schemas.mkDir
    if (!state.requireLogin(schema)) return

    val clientPath = schema.getCryptoString("ClientPath", state.message.data)!!

    val serverPath = schema.getPath("Path", state.message.data)!!
    if (serverPath.isRoot() || serverPath.isFile()) {
        state.quickResponse(400, "BAD REQUEST", "Bad path $serverPath given")
        return
    }
    val parent = serverPath.parent() ?: state.internalError(
        "Failed to get parent for path $serverPath",
        "Error getting parent for $serverPath"
    ).run { return }

    val lfs = LocalFS.get()
    checkDirectoryAccess(state, lfs.entry(parent), AuthAction.Create).onFalse { return }

    val dirHandle = lfs.entry(serverPath)
    dirHandle.makeDirectory()?.let {
        state.internalError(
            "Failed to create $serverPath: $it",
            "Error creating directory"
        )
        return
    }

    val db = state.dbConnect() ?: return
    addFolderEntry(db, state.wid!!, serverPath, clientPath)?.let {
        dirHandle.delete()?.let { e -> logError("Failed to delete folder $serverPath: $e") }
        state.internalError(
            "Failed to add folder entry for $serverPath: $it",
            "Error creating folder entry"
        )
        db.disconnect()
        return
    }

    addSyncRecord(
        db, state.wid!!, SyncRecord(
            RandomID.generate(),
            UpdateType.Mkdir,
            "$serverPath:$clientPath",
            Instant.now().epochSecond.toString(),
            state.devid!!
        )
    )?.let {
        state.internalError(
            "commandMkDir: failed to add update entry for $serverPath: $it",
            "Error adding update entry"
        )
        db.disconnect()
        return
    }
    db.disconnect()
    state.quickResponse(200, "OK")
}

// MOVE(SourceFile,DestDir)
fun commandMove(state: ClientSession) {
    val schema = Schemas.move
    if (!state.requireLogin(schema)) return
    val sourceFilePath = schema.getPath("SourceFile", state.message.data)!!
    if (!sourceFilePath.isFile()) {
        state.quickResponse(404, "BAD REQUEST", "SourceFile must be a file path")
        return
    }
    val destPath = schema.getPath("DestDir", state.message.data)!!
    if (!destPath.isDir()) {
        state.quickResponse(
            404, "BAD REQUEST",
            "DestDir must be a directory"
        )
        return
    }

    val lfs = LocalFS.get()
    checkDirectoryAccess(
        state,
        lfs.entry(sourceFilePath.parent()!!),
        AuthAction.Access
    ).onFalse { return }
    checkDirectoryAccess(state, lfs.entry(destPath), AuthAction.Create).onFalse { return }

    lfs.withLock(sourceFilePath) {
        sourceFilePath.toHandle().moveTo(destPath)
    }?.let {
        state.internalError(
            "Error copying file $sourceFilePath to $destPath: $it",
            "Internal error copying file"
        )
        return
    }

    withDB { db ->
        addSyncRecord(
            db, state.wid!!, SyncRecord(
                RandomID.generate(),
                UpdateType.Move,
                "$sourceFilePath:$destPath",
                Instant.now().epochSecond.toString(),
                state.devid!!
            )
        )?.let {
            state.internalError(
                "commandMove: failed to add update entry for $destPath: $it",
                "Error adding update entry for created file"
            )
            db.disconnect()
            return
        }
    }.onFalse { return }

    state.quickResponse(200, "OK")
}

// RMDIR(Path, ClientPath)
fun commandRmDir(state: ClientSession) {
    val schema = Schemas.rmDir
    if (!state.requireLogin(schema)) return

    val serverPath = schema.getPath("Path", state.message.data)!!
    if (serverPath.isFile() || serverPath.isRoot()) {
        state.quickResponse(400, "BAD REQUEST", "Bad path $serverPath given")
        return
    }

    val parent = serverPath.parent() ?: state.internalError(
        "Failed to get parent for path $serverPath",
        "Error getting parent for $serverPath"
    ).run { return }

    val lfs = LocalFS.get()
    checkDirectoryAccess(state, lfs.entry(parent), AuthAction.Delete).onFalse { return }

    val dirHandle = lfs.entry(serverPath)
    dirHandle.delete()?.let {
        state.internalError(
            "Failed to delete $serverPath: $it",
            "Error deleting directory"
        )
        return
    }

    val db = state.dbConnect() ?: return
    removeFolderEntry(db, state.wid!!, serverPath)?.let {
        state.internalError(
            "Failed to delete folder entry for $serverPath: $it",
            "Error deleting folder entry"
        )
        db.disconnect()
        return
    }

    addSyncRecord(
        db, state.wid!!, SyncRecord(
            RandomID.generate(),
            UpdateType.Rmdir,
            "$serverPath",
            Instant.now().epochSecond.toString(),
            state.devid!!
        )
    )?.let {
        state.internalError(
            "commandRmDir: failed to add update entry for $serverPath: $it",
            "Error adding update entry"
        )
        db.disconnect()
        return
    }
    db.disconnect()
    state.quickResponse(200, "OK")
}

// SELECT(Path)
fun commandSelect(state: ClientSession) {
    val schema = Schemas.select
    if (!state.requireLogin(schema)) return

    val entry = schema.getPath("Path", state.message.data)!!.toHandle()
    checkDirectoryAccess(state, entry, AuthAction.Access).onFalse { return }

    state.currentPath = entry.path
    state.quickResponse(200, "OK")
}

// SETQUOTA(Workspace-ID, Size)
fun commandSetQuota(state: ClientSession) {
    val schema = Schemas.setQuotaInfo
    if (!state.requireLogin(schema)) return

    val wid = schema.getRandomID("Workspace-ID", state.message.data)!!
    val size = schema.getLong("Size", state.message.data)!!
    checkWorkspaceAccess(state, wid, AuthAction.SetQuota).onFalse { return }
    withDB { db ->
        setQuota(db, wid, size)?.let {
            state.internalError(
                "Error setting quota info for $wid: $it",
                "Server error setting disk quota info"
            )
            db.disconnect()
            return
        }
    }.onFalse { return }

    state.quickResponse(200, "OK")
}

// UPLOAD(Size,Hash,Path,Replaces="",Name="",Offset=0)
fun commandUpload(state: ClientSession) {

    val schema = Schemas.upload
    if (!state.requireLogin(schema)) return

    val clientHash = schema.getCryptoString("Hash", state.message.data)!!.toHash() ?: run {
        state.quickResponse(400, "BAD REQUEST", "Invalid value for Hash")
        return
    }

    // Both TempName and Offset must be present when resuming
    var tempName = schema.getString("TempName", state.message.data)
    if (tempName != null && !MServerPath.checkFileName(tempName)) {
        state.quickResponse(400, "BAD REQUEST", "Invalid value for field TempName")
        return
    }
    val resumeOffset = schema.getLong("Offset", state.message.data)
    if ((tempName == null && resumeOffset != null) || (tempName != null && resumeOffset == null)) {
        state.quickResponse(
            400, "BAD REQUEST",
            "Upload resume requires both TempName and Offset fields",
        )
        return
    }

    val lfs = LocalFS.get()
    val replacesPath = state.getPath("Replaces", false)
    if (replacesPath != null) {
        val handle = runCatching { lfs.entry(replacesPath) }.getOrElse {
            state.internalError(
                "Error opening path $replacesPath: $it",
                "commandUpload.1 error"
            )
            return
        }

        handle.exists().getOrElse {
            state.internalError(
                "Error checking existence of $replacesPath: $it",
                "commandUpload.2 error"
            )
            return
        }.onFalse {
            state.quickResponse(404, "NOT FOUND", "$replacesPath doesn't exist")
            return
        }
    }

    val fileSize = schema.getLong("Size", state.message.data)!!
    val uploadPath = schema.getPath("Path", state.message.data)!!

    // The DirectoryTarget constructor validates that the target path points to a directory
    val dirTarget = DirectoryTarget.fromPath(uploadPath) ?: state.quickResponse(
        400,
        "BAD REQUEST",
        "Upload path must be a directory"
    ).run { return }

    dirTarget.isAuthorized(WIDActor(state.wid!!), AuthAction.Create)
        .getOrElse {
            state.internalError(
                "commandUpload: Auth check error: $it",
                "Error checking authorization"
            )
            return
        }.onFalse {
            state.quickResponse(403, "FORBIDDEN")
            return
        }

    val uploadPathHandle = lfs.entry(uploadPath)
    uploadPathHandle.exists().getOrElse {
        state.internalError(
            "Error checking existence of $uploadPath: $it",
            "Error checking for upload path"
        )
        return
    }.onFalse {
        state.quickResponse(404, "NOT FOUND", "$uploadPathHandle doesn't exist")
        return
    }

    val config = ServerConfig.get()
    if (fileSize > config.getInteger("performance.max_file_size")!! * 0x10_000) {
        state.quickResponse(
            414, "LIMIT REACHED",
            "File size greater than max allowed on server"
        )
        return
    }

    // Arguments have been validated, do a quota check

    val db = state.dbConnect() ?: return
    val quotaInfo = getQuotaInfo(db, state.wid!!).getOrElse {
        state.internalError(
            "Error getting quota for wid ${state.wid!!}: $it",
            "Server error getting account quota info"
        )
        db.disconnect()
        return
    }

    if (quotaInfo.second > 0 && quotaInfo.first + fileSize > quotaInfo.second) {
        state.quickResponse(
            409, "QUOTA INSUFFICIENT",
            "Your account lacks sufficient space for the file"
        )
        db.disconnect()
        return
    }

    // This works because if resumeOffset == null, tempName must also be null at this point. We're
    // given a temporary name by the client only when resuming. Being that we have to have a name
    // for the temporary file, we create one here.
    if (resumeOffset == null)
        tempName =
            "${Instant.now().epochSecond}.$fileSize.${UUID.randomUUID().toString().lowercase()}"
    val tempPath = MServerPath.fromString("/ tmp ${state.wid!!} $tempName")!!

    ServerResponse(100, "CONTINUE", "", mutableMapOf("TempName" to tempName!!))
        .sendCatching(
            state.conn,
            "commandUpload: Error sending continue message for wid ${state.wid!!}"
        ).onFalse {
            db.disconnect()
            return
        }

    val tempHandle = lfs.entry(tempPath)
    state.readFileData(fileSize, tempHandle, resumeOffset)?.let {
        // Transfer was interrupted. We won't delete the file--we will leave it so the client can
        // attempt to resume the upload later.
        ServerResponse(
            305, "INTERRUPTED",
            "Interruption source: $it"
        ).sendCatching(state.conn, "Upload interrupted for wid ${state.wid}")
        db.disconnect()
        return
    }

    val serverHash = tempHandle.hashFile(clientHash.getType()!!).getOrElse {
        if (it is UnsupportedAlgorithmException) {
            state.quickResponse(
                309, "UNSUPPORTED ALGORITHM",
                "Hash algorithm ${clientHash.prefix} not unsupported"
            )
        } else {
            state.internalError(
                "commandUpload: Error hashing file: $it",
                "Server error hashing file"
            )
        }
        db.disconnect()
        return
    }

    if (serverHash != clientHash) {
        tempHandle.delete()?.let {
            logError("commandUpload: Error deleting invalid temp file: $it")
        }
        state.quickResponse(410, "HASH MISMATCH", "Hash mismatch on uploaded file")
        db.disconnect()
        return
    }

    tempHandle.moveTo(uploadPath)?.let {
        state.internalError(
            "commandUpload: Error installing temp file: $it",
            "Server error finishing upload"
        )
        db.disconnect()
        return
    }

    val unixTime = System.currentTimeMillis() / 1000L
    if (replacesPath != null) {
        lfs.withLock(replacesPath) { lfs.entry(it).delete() }

        addSyncRecord(
            db, state.wid!!, SyncRecord(
                RandomID.generate(), UpdateType.Replace, "$replacesPath:$uploadPath",
                unixTime.toString(), state.devid!!
            )
        )
    } else {
        modifyQuotaUsage(db, state.wid!!, fileSize).getOrElse {
            state.internalError(
                "commandUpload: Error adjusting quota usage: $it",
                "Server account quota error"
            )
            db.disconnect()
            return
        }

        addSyncRecord(
            db, state.wid!!, SyncRecord(
                RandomID.generate(), UpdateType.Create, uploadPath.toString(),
                unixTime.toString(), state.devid!!
            )
        )
    }
    db.disconnect()

    val ok = ServerResponse(200, "OK")
    ok.data["FileName"] = tempHandle.path.basename()
    ok.sendCatching(
        state.conn,
        "commandUpload: Couldn't send confirmation response for wid = ${state.wid}"
    )
}

private fun checkDirectoryAccess(state: ClientSession, entry: LocalFSHandle, access: AuthAction):
        Boolean {
    entry.exists().getOrElse {
        state.internalError(
            "${state.message.action}: error checking for directory ${entry.path}: $it",
            "Error checking directory existence"
        )
        return false
    }.onFalse {
        state.quickResponse(404, "RESOURCE NOT FOUND")
        return false
    }

    val dir = DirectoryTarget.fromPath(entry.path) ?: state.quickResponse(
        400, "BAD REQUEST",
        "Path given must be a directory"
    ).run { return false }
    dir.isAuthorized(WIDActor(state.wid!!), access)
        .getOrElse {
            state.internalError(
                "Failed to check authorization of ${state.wid} in path $dir: $it",
                "Error checking authorization"
            )
            return false
        }.onFalse {
            state.quickResponse(403, "FORBIDDEN")
            return false
        }
    return true
}

private fun checkWorkspaceAccess(state: ClientSession, targetWID: RandomID, access: AuthAction):
        Boolean {
    val workspace = WorkspaceTarget.fromWID(targetWID).getOrElse {
        logError("${state.message.action}.WorkspaceTarget exception: $it")
        state.quickResponse(300, "INTERNAL SERVER ERROR", "Error finding workspace")
        return false
    }
    if (workspace == null) {
        state.quickResponse(404, "NOT FOUND")
        return false
    }

    workspace.isAuthorized(WIDActor(state.wid!!), access)
        .getOrElse {
            logError("${state.message.action}.checkAuth exception: $it")
            state.quickResponse(
                300, "INTERNAL SERVER ERROR",
                "authorization check error"
            )
            return false
        }.onFalse {
            state.quickResponse(403, "FORBIDDEN")
            return false
        }
    return true
}

/**
 * Returns true if the user's quota can accommodate an increase in disk usage of the specified
 * amount of space.
 */
private fun checkQuota(state: ClientSession, fileSize: Int): Boolean? {
    val db = state.dbConnect() ?: run {
        state.unavailableError()
        return null
    }
    val quotaInfo = getQuotaInfo(db, state.wid!!).getOrElse {
        state.internalError(
            "Error getting quota for wid ${state.wid!!}: $it",
            "Server error getting account quota info"
        )
        db.disconnect()
        return null
    }

    if (quotaInfo.second > 0 && quotaInfo.first + fileSize > quotaInfo.second) {
        state.quickResponse(
            409, "QUOTA INSUFFICIENT",
            "Your account lacks sufficient space for the file"
        )
        db.disconnect()
        return false
    }
    db.disconnect()
    return true
}