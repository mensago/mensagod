package mensagod.handlers

import keznacl.UnsupportedAlgorithmException
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

// DOWNLOAD(Path,Offset=0)
fun commandDownload(state: ClientSession) {

    if (!state.requireLogin()) return
    val path = state.getPath("Path", true) ?: return
    val lfs = LocalFS.get()
    val handle = lfs.entry(path)

    // The FileTarget class verifies that the path is, indeed, pointing to a file
    val fileTarget = FileTarget.fromPath(path)
    if (fileTarget == null) {
        QuickResponse.sendBadRequest("Path must be for a file", state.conn)
        return
    }
    val isAuthorized = fileTarget.isAuthorized(WIDActor(state.wid!!), AuthAction.Read)
        .getOrElse {
            logError("commandDownload: Auth check error: $it")
            QuickResponse.sendInternalError("Error checking authorization", state.conn)
            return
        }
    if (!isAuthorized) {
        QuickResponse.sendForbidden("", state.conn)
        return
    }
    val exists = handle.exists().getOrElse {
        logError("commandDownload: Error checking existence of $path: $it")
        QuickResponse.sendInternalError("Error checking path existence", state.conn)
        return
    }
    if (!exists) {
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

// UPLOAD(Size,Hash,Path,Replaces="",Name="",Offset=0)
fun commandUpload(state: ClientSession) {

    if (!state.requireLogin()) return
    state.message.validate(setOf("Size", "Path", "Hash"))?.let {
        QuickResponse.sendBadRequest("Missing required field $it", state.conn)
        return
    }

    val clientHash = state.getCryptoString("Hash", true)
    if (clientHash == null) {
        QuickResponse.sendBadRequest("Invalid value for Hash", state.conn)
        return
    }

    // Both TempName and Offset must be present when resuming
    val hasTempName = state.message.hasField("TempName")
    val hasOffset = state.message.hasField("Offset")
    if ((hasTempName && !hasOffset) || (!hasTempName && hasOffset)) {
        QuickResponse.sendBadRequest(
            "Upload resume requires both TempName and Offset fields",
            state.conn
        )
        return
    }

    val lfs = LocalFS.get()
    val replacesPath = state.getPath("Replaces", false)
    if (replacesPath != null) {
        val handle = try {
            lfs.entry(replacesPath)
        } catch (e: SecurityException) {
            logError("Error opening path $replacesPath: $e")
            QuickResponse.sendInternalError("commandUpload.1 error", state.conn)
            return
        }

        val exists = handle.exists().getOrElse {
            logError("Error checking existence of $replacesPath: $it")
            QuickResponse.sendInternalError("commandUpload.2 error", state.conn)
            return
        }
        if (!exists) {
            ServerResponse(404, "NOT FOUND", "$replacesPath doesn't exist")
                .sendCatching(state.conn, "Client requested nonexistent path $replacesPath")
            return
        }
    } else if (state.message.hasField("Replaces")) {
        QuickResponse.sendBadRequest("Invalid value for Replaces", state.conn)
        return
    }

    val fileSize = try {
        state.message.data["Size"]!!.toLong()
    } catch (e: Exception) {
        QuickResponse.sendBadRequest("Invalid value for Size", state.conn)
        return
    }

    val uploadPath = state.getPath("Path", true)
    if (uploadPath == null) {
        QuickResponse.sendBadRequest("Invalid value for field Path", state.conn)
        return
    }
    // The DirectoryTarget constructor validates that the target path points to a directory
    val dirTarget = DirectoryTarget.fromPath(uploadPath)
    if (dirTarget == null) {
        QuickResponse.sendBadRequest("Upload path must be a directory", state.conn)
        return
    }
    val isAuthorized = dirTarget.isAuthorized(WIDActor(state.wid!!), AuthAction.Create)
        .getOrElse {
            logError("commandUpload: Auth check error: $it")
            QuickResponse.sendInternalError("Error checking authorization", state.conn)
            return
        }
    if (!isAuthorized) {
        QuickResponse.sendForbidden("", state.conn)
        return
    }

    val uploadPathHandle = try {
        lfs.entry(uploadPath)
    } catch (e: SecurityException) {
        logError("Error opening path $uploadPath: $e")
        QuickResponse.sendInternalError("commandUpload.3 error", state.conn)
        return
    }
    val exists = uploadPathHandle.exists().getOrElse {
        logError("Error checking existence of $uploadPath: $it")
        QuickResponse.sendInternalError("commandUpload.4 error", state.conn)
        return
    }
    if (!exists) {
        ServerResponse(404, "NOT FOUND", "$uploadPathHandle doesn't exist")
            .sendCatching(state.conn, "Client requested nonexistent path $uploadPathHandle")
        return
    }

    val resumeOffset: Long?
    if (hasTempName) {
        if (!MServerPath.validateFileName(state.message.data["TempName"]!!)) {
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

    val serverHash = tempHandle.hashFile(clientHash.prefix).getOrElse {
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

        addUpdateRecord(
            db, state.wid!!, UpdateRecord(
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

        addUpdateRecord(
            db, state.wid!!, UpdateRecord(
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

