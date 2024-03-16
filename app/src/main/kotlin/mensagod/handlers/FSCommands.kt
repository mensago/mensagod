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

    val offset = if (state.message.hasField("Offset")) {
        try {
            state.message.data["Offset"]!!.toLong()
        } catch (e: Exception) {
            state.quickResponse(400, "BAD REQUEST", "Invalid value for Offset")
            return
        }
    } else 0L
    val fileSize = handle.size().getOrElse {
        logError("commandDownload: Error getting size of $path: $it")
        QuickResponse.sendInternalError("Error getting file size", state.conn)
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
        state.quickResponse(400, "BAD REQUEST", "Bad path $serverPath given")
        return
    }

    val parent = serverPath.parent() ?: state.internalError(
        "Failed to get parent for path $serverPath",
        "Error getting parent for $serverPath"
    ).run { return }

    val lfs = LocalFS.get()
    lfs.entry(parent).exists().getOrElse {
        state.internalError(
            "Failed to check existence of parent path $parent: $it",
            "Error checking parent path"
        )
        return
    }.onFalse {
        if (parent.toString() == "/ wsp ${state.wid!!}") {
            val parentHandle = lfs.entry(parent)
            parentHandle.makeDirectory()?.let {
                state.internalError(
                    "commandMkDir: failed to create workspace dir $parent: $it",
                    "Error creating workspace path"
                )
                return
            }
        } else {
            state.quickResponse(404, "NOT FOUND", "Parent path not found")
            return
        }
    }

    DirectoryTarget.fromPath(parent)!!
        .isAuthorized(WIDActor(state.wid!!), AuthAction.Create)
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
    dirHandle.makeDirectory()?.let {
        state.internalError(
            "Failed to create $serverPath: $it",
            "Error creating directory"
        )
        return
    }

    val db = DBConn()
    addFolderEntry(db, state.wid!!, serverPath, clientPath)?.let {
        dirHandle.delete()?.let { e -> logError("Failed to delete folder $serverPath: $e") }
        state.internalError(
            "Failed to add folder entry for $serverPath: $it",
            "Error creating folder entry"
        )
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
    dir.isAuthorized(WIDActor(state.wid!!), AuthAction.Access)
        .getOrElse {
            state.internalError(
                "Failed to check authorization of ${state.wid} in path $dir: $it",
                "Error checking authorization"
            )
            return
        }.onFalse {
            state.quickResponse(403, "FORBIDDEN")
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

    val db = DBConn()
    val quotaInfo = getQuotaInfo(db, state.wid!!).getOrElse {
        state.internalError(
            "Error getting quota for wid ${state.wid!!}: $it",
            "Server error getting account quota info"
        )
        return
    }

    if (quotaInfo.second > 0 && quotaInfo.first + fileSize > quotaInfo.second) {
        state.quickResponse(
            409, "QUOTA INSUFFICIENT",
            "Your account lacks sufficient space for the file"
        )
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
        ).onFalse { return }

    val tempHandle = lfs.entry(tempPath)
    state.readFileData(fileSize, tempHandle, resumeOffset)?.let {
        // Transfer was interrupted. We won't delete the file--we will leave it so the client can
        // attempt to resume the upload later.
        ServerResponse(
            305, "INTERRUPTED",
            "Interruption source: $it"
        ).sendCatching(state.conn, "Upload interrupted for wid ${state.wid}")
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
        return
    }

    if (serverHash != clientHash) {
        tempHandle.delete()?.let {
            logError("commandUpload: Error deleting invalid temp file: $it")
        }
        state.quickResponse(410, "HASH MISMATCH", "Hash mismatch on uploaded file")
        return
    }

    tempHandle.moveTo(uploadPath)?.let {
        state.internalError(
            "commandUpload: Error installing temp file: $it",
            "Server error finishing upload"
        )
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

