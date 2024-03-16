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
import mensagod.auth.AuthAction
import mensagod.auth.DirectoryTarget
import mensagod.auth.FileTarget
import mensagod.auth.WIDActor
import mensagod.dbcmds.*
import java.time.Instant
import java.util.*

// COPY(SourceFile,DestDir)
fun commandCopy(state: ClientSession) {
    if (!state.requireLogin()) return

    TODO("Implement commandCopy($state)")
}

// DELETE(PathCount,Path0...)
fun commandDelete(state: ClientSession) {
    if (!state.requireLogin()) return

    TODO("Implement commandDelete($state)")
}

// DOWNLOAD(Path,Offset=0)
fun commandDownload(state: ClientSession) {

    if (!state.requireLogin()) return
    val path = state.getPath("Path", true) ?: return
    val lfs = LocalFS.get()
    val handle = lfs.entry(path)

    // The FileTarget class verifies that the path is, indeed, pointing to a file
    val fileTarget = FileTarget.fromPath(path) ?: run {
        state.quickResponse(400, "BAD REQUEST", "Path must be for a file")
        return
    }
    fileTarget.isAuthorized(WIDActor(state.wid!!), AuthAction.Read)
        .getOrElse {
            logError("commandDownload: Auth check error: $it")
            QuickResponse.sendInternalError("Error checking authorization", state.conn)
            return
        }.onFalse {
            state.quickResponse(403, "FORBIDDEN")
            return
        }

    handle.exists().getOrElse {
        logError("commandDownload: Error checking existence of $path: $it")
        QuickResponse.sendInternalError("Error checking path existence", state.conn)
        return
    }.onFalse {
        ServerResponse(404, "RESOURCE NOT FOUND").sendCatching(
            state.conn,
            "Error sending 404 error to client for wid ${state.wid}"
        )
        return
    }

    val offset = if (state.message.hasField("Offset")) {
        try {
            state.message.data["Offset"]!!.toLong()
        } catch (e: Exception) {
            QuickResponse.sendBadRequest("Invalid value for Offset", state.conn)
            return
        }
    } else 0L
    val fileSize = handle.size().getOrElse {
        logError("commandDownload: Error getting size of $path: $it")
        QuickResponse.sendInternalError("Error getting file size", state.conn)
        return
    }
    if (offset < 0 || offset > fileSize) {
        QuickResponse.sendBadRequest("Offset out of range", state.conn)
        return
    }

    ServerResponse(
        100, "CONTINUE", "",
        mutableMapOf("Size" to fileSize.toString())
    ).send(state.conn)?.let {
        logDebug("commandDownload: Error sending continue message for wid ${state.wid!!}: $it")
        return
    }

    val req = ClientRequest.receive(state.conn.getInputStream()).getOrElse {
        logDebug("commandDownload: error receiving client continue request: $it")
        return
    }
    if (req.action == "CANCEL") return

    if (req.action != "DOWNLOAD" || !req.hasField("Size")) {
        QuickResponse.sendBadRequest("Session mismatch", state.conn)
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

    val exists = entry.exists().getOrElse {
        logError("Error checking existence of ${entry.path}: $it")
        QuickResponse.sendInternalError("Error checking existence of path", state.conn)
        return
    }
    val response = if (exists) ServerResponse(200, "OK", "")
    else ServerResponse(404, "NOT FOUND", "")
    response.sendCatching(state.conn, "Failed to send MKDIR confirmation")
}

// GETQUOTAINFO(Workspace=null)
fun commandGetQuotaInfo(state: ClientSession) {
    TODO("Implement commandGetQuotaInfo($state)")
}

// LIST(Path=null)
fun commandList(state: ClientSession) {
    if (!state.requireLogin()) return

    TODO("Implement commandList($state)")
}

// LISTDIRS(Path=null)
fun commandListDirs(state: ClientSession) {
    if (!state.requireLogin()) return

    TODO("Implement commandListDirs($state)")
}

// MKDIR(Path, ClientPath)
fun commandMkDir(state: ClientSession) {
    val schema = Schemas.mkDir
    if (!state.requireLogin(schema)) return

    val clientPath = schema.getCryptoString("ClientPath", state.message.data)!!

    val serverPath = schema.getPath("Path", state.message.data)!!
    if (serverPath.isFile() || serverPath.isRoot()) {
        QuickResponse.sendBadRequest("Bad path $serverPath given", state.conn)
        return
    }

    val parent = serverPath.parent()
    if (parent == null) {
        logError("Failed to get parent for path $serverPath")
        QuickResponse.sendInternalError("Error getting parent for $serverPath", state.conn)
        return
    }

    val lfs = LocalFS.get()
    val exists = lfs.entry(parent).exists().getOrElse {
        logError("Failed to check existence of parent path $parent: $it")
        QuickResponse.sendInternalError("Error checking parent path", state.conn)
        return
    }
    if (!exists) {
        if (parent.toString() == "/ wsp ${state.wid!!}") {
            val parentHandle = lfs.entry(parent)
            parentHandle.makeDirectory()?.let {
                logError("commandMkDir: failed to create workspace dir $parent: $it")
                QuickResponse.sendInternalError("Error creating workspace path", state.conn)
                return
            }
        } else {
            QuickResponse.sendNotFound("Parent path not found", state.conn)
            return
        }
    }

    DirectoryTarget.fromPath(parent)!!
        .isAuthorized(WIDActor(state.wid!!), AuthAction.Create)
        .getOrElse {
            logError("Failed to check authorization of ${state.wid} in path $parent: $it")
            QuickResponse.sendInternalError("Error checking authorization", state.conn)
            return
        }.onFalse {
            state.quickResponse(403, "FORBIDDEN")
            return
        }

    val dirHandle = lfs.entry(serverPath)
    dirHandle.makeDirectory()?.let {
        logError("Failed to create $serverPath: $it")
        QuickResponse.sendInternalError("Error creating directory", state.conn)
        return
    }

    val db = DBConn()
    addFolderEntry(db, state.wid!!, serverPath, clientPath)?.let {
        dirHandle.delete()?.let { e -> logError("Failed to delete folder $serverPath: $e") }
        logError("Failed to add folder entry for $serverPath: $it")
        QuickResponse.sendInternalError("Error creating folder entry", state.conn)
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
        logError("commandMkDir: failed to add update entry for $serverPath: $it")
        QuickResponse.sendInternalError("Error adding update entry", state.conn)
        return
    }
    state.quickResponse(200, "OK")
}

// MOVE(SourceFile,DestDir)
fun commandMove(state: ClientSession) {
    TODO("Implement commandMove($state)")
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
    lfs.entry(parent).exists()
        .getOrElse {
            state.internalError(
                "Failed to check existence of parent path $parent: $it",
                "Error checking parent path"
            )
            return
        }.onFalse {
            state.quickResponse(404, "NOT FOUND", "Parent path not found")
            return
        }

    DirectoryTarget.fromPath(parent)!!
        .isAuthorized(WIDActor(state.wid!!), AuthAction.Delete)
        .getOrElse {
            state.internalError(
                "Failed to check authorization of ${state.wid} in path $parent: $it",
                "Error checking authorization"
            )
            return
        }.onFalse {
            state.quickResponse(403, "FORBIDDEN")
            return
        }

    val dirHandle = lfs.entry(serverPath)
    dirHandle.delete()?.let {
        state.internalError(
            "Failed to delete $serverPath: $it",
            "Error deleting directory"
        )
        return
    }

    val db = DBConn()
    removeFolderEntry(db, state.wid!!, serverPath)?.let {
        state.internalError(
            "Failed to delete folder entry for $serverPath: $it",
            "Error deleting folder entry"
        )
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
        return
    }
    state.quickResponse(200, "OK")
}

// SELECT(Path)
fun commandSelect(state: ClientSession) {
    val schema = Schemas.select
    if (!state.requireLogin(schema)) return

    val entry = schema.getPath("Path", state.message.data)!!.toHandle()
    entry.exists().getOrElse {
        state.internalError(
            "commandSelect: error checking for directory ${entry.path}: $it",
            "Error checking directory existence"
        )
        return
    }.onFalse {
        state.quickResponse(404, "RESOURCE NOT FOUND")
        return
    }

    val dir = DirectoryTarget.fromPath(entry.path) ?: state.quickResponse(
        400, "BAD REQUEST",
        "Path given must be a directory"
    ).run { return }
    dir.isAuthorized(WIDActor(state.wid!!), AuthAction.Read)
        .getOrElse {
            state.internalError(
                "Failed to check authorization of ${state.wid} in path $dir: $it",
                "Error checking authorization"
            )
            return
        }.onFalse {
            QuickResponse.sendForbidden("", state.conn)
            return
        }

    state.currentPath = entry.path
    state.quickResponse(200, "OK")
}

// SETQUOTA(Workspace)
fun commandSetQuota(state: ClientSession) {
    TODO("Implement commandSetQuota($state)")
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
    val hasTempName = state.message.hasField("TempName")
    val hasOffset = state.message.hasField("Offset")
    if ((hasTempName && !hasOffset) || (!hasTempName && hasOffset)) {
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
            logError("commandUpload: Auth check error: $it")
            QuickResponse.sendInternalError("Error checking authorization", state.conn)
            return
        }.onFalse {
            QuickResponse.sendForbidden("", state.conn)
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

    val resumeOffset: Long?
    if (hasTempName) {
        if (!MServerPath.checkFileName(state.message.data["TempName"]!!)) {
            QuickResponse.sendBadRequest("Invalid value for field TempName", state.conn)
            return
        }

        resumeOffset = try {
            state.message.data["Offset"]!!.toLong()
        } catch (e: Exception) {
            QuickResponse.sendBadRequest("Invalid value for field Offset", state.conn)
            return
        }
        if (resumeOffset!! < 1 || resumeOffset > fileSize) {
            QuickResponse.sendBadRequest("Invalid value for field Offset", state.conn)
            return
        }
    } else resumeOffset = null

    val config = ServerConfig.get()
    if (fileSize > config.getInteger("performance.max_file_size")!! * 0x10_000) {
        ServerResponse(
            414, "LIMIT REACHED",
            "File size greater than max allowed on server"
        )
            .sendCatching(state.conn, "Client requested file larger than configured max")
        return
    }

    // Arguments have been validated, do a quota check

    val db = DBConn()
    val quotaInfo = getQuotaInfo(db, state.wid!!).getOrElse {
        logError("Error getting quota for wid ${state.wid!!}: $it")
        QuickResponse.sendInternalError("Server error getting account quota info", state.conn)
        return
    }

    if (quotaInfo.second > 0 && quotaInfo.first + fileSize > quotaInfo.second) {
        ServerResponse(
            409, "QUOTA INSUFFICIENT",
            "Your account lacks sufficient space for the file"
        )
            .sendCatching(state.conn, "Client requested file larger than free space")
        return
    }

    val tempName = if (resumeOffset != null)
        state.message.data["TempName"]!!
    else
        "${Instant.now().epochSecond}.$fileSize.${UUID.randomUUID().toString().lowercase()}"
    val tempPath = MServerPath.fromString("/ tmp ${state.wid!!} $tempName")!!

    ServerResponse(100, "CONTINUE", "", mutableMapOf("TempName" to tempName))
        .send(state.conn)?.let {
            logDebug("commandUpload: Error sending continue message for wid ${state.wid!!}: $it")
            return
        }

    val tempHandle = lfs.entry(tempPath)
    state.readFileData(fileSize, tempHandle, resumeOffset)?.let {
        // Transfer was interrupted. We won't delete the file--we will leave it so the client can
        // attempt to resume the upload later.
        ServerResponse(
            305, "INTERRUPTED",
            "Interruption source: $it"
        )
            .sendCatching(state.conn, "Upload interrupted for wid ${state.wid}")
        return
    }

    val serverHash = tempHandle.hashFile(clientHash.getType()!!).getOrElse {
        if (it is UnsupportedAlgorithmException) {
            ServerResponse(
                309, "UNSUPPORTED ALGORITHM",
                "Hash algorithm ${clientHash.prefix} not unsupported"
            )
                .sendCatching(state.conn, "Client requested unsupported hash algorithm")
        } else {
            logError("commandUpload: Error hashing file: $it")
            QuickResponse.sendInternalError("Server error hashing file", state.conn)
        }
        return
    }

    if (serverHash != clientHash) {
        tempHandle.delete()?.let {
            logError("commandUpload: Error deleting invalid temp file: $it")
        }
        ServerResponse(410, "HASH MISMATCH").sendCatching(
            state.conn,
            "Hash mismatch on uploaded file"
        )
        return
    }

    tempHandle.moveTo(uploadPath)?.let {
        logError("commandUpload: Error installing temp file: $it")
        QuickResponse.sendInternalError("Server error finishing upload", state.conn)
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
            logError("commandUpload: Error adjusting quota usage: $it")
            QuickResponse.sendInternalError("Server account quota error", state.conn)
            return
        }

        addSyncRecord(
            db, state.wid!!, SyncRecord(
                RandomID.generate(), UpdateType.Create, uploadPath.toString(),
                unixTime.toString(), state.devid!!
            )
        )
    }

    val ok = ServerResponse(200, "OK")
    ok.data["FileName"] = tempHandle.path.basename()
    ok.sendCatching(
        state.conn,
        "commandUpload: Couldn't send confirmation response for wid = ${state.wid}"
    )
}

