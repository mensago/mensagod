package mensagod.commands

import keznacl.UnsupportedAlgorithmException
import libkeycard.RandomID
import mensagod.*
import mensagod.dbcmds.UpdateRecord
import mensagod.dbcmds.UpdateType
import mensagod.dbcmds.addUpdateRecord
import mensagod.dbcmds.getQuotaInfo
import mensagod.fs.LocalFS
import mensagod.fs.LocalFSHandle
import java.time.Instant
import java.util.*

// UPLOAD(Size,Hash,Path,Replaces="",Name="",Offset=0)
fun commandUpload(state: ClientSession) {

    if (!state.requireLogin()) return
    state.message.validate(setOf("Size", "Path", "Hash"))?.let{
        ServerResponse.sendBadRequest("Missing required field $it", state.conn)
        return
    }

    val clientHash = state.getCryptoString("Hash", true)
    if (clientHash == null) {
        ServerResponse.sendBadRequest("Invalid value for Hash", state.conn)
        return
    }

    // Both TempName and Offset must be present when resuming
    val hasTempName = state.message.hasField("TempName")
    val hasOffset = state.message.hasField("Offset")
    if ( (hasTempName && !hasOffset) || (!hasTempName && hasOffset)) {
        ServerResponse.sendBadRequest("Upload resume requires both TempName and Offset fields",
            state.conn)
        return
    }

    val lfs = LocalFS.get()
    val replacesPath = state.getPath("Replaces", false)
    if (replacesPath != null) {
        val handle = try { lfs.entry(replacesPath) }
        catch (e: SecurityException) {
            logError("Error opening path $replacesPath: $e")
            ServerResponse.sendInternalError("commandUpload.1 error", state.conn)
            return
        }

        if (!handle.exists()) {
            ServerResponse(404, "NOT FOUND", "$replacesPath doesn't exist")
                .sendCatching(state.conn, "Client requested nonexistent path $replacesPath")
            return
        }
    } else if (state.message.hasField("Replaces")) {
        ServerResponse.sendBadRequest("Invalid value for Replaces", state.conn)
        return
    }

    val fileSize = try { state.message.data["Size"]!!.toInt() }
    catch (e: Exception) {
        ServerResponse.sendBadRequest("Invalid value for Size", state.conn)
        return
    }

    val uploadPath = state.getPath("Path", true)
    if (uploadPath == null) {
        ServerResponse.sendBadRequest("Invalid value for field Path", state.conn)
        return
    }
    val uploadPathHandle = try { lfs.entry(uploadPath) }
    catch (e: SecurityException) {
        logError("Error opening path $replacesPath: $e")
        ServerResponse.sendInternalError("commandUpload.2 error", state.conn)
        return
    }
    if (!uploadPathHandle.exists()) {
        ServerResponse(404, "NOT FOUND", "$uploadPathHandle doesn't exist")
            .sendCatching(state.conn, "Client requested nonexistent path $uploadPathHandle")
        return
    }

    val resumeOffset: Int?
    if (hasTempName) {
        if (!MServerPath.validateFileName(state.message.data["TempName"]!!)) {
            ServerResponse.sendBadRequest("Invalid value for field TempName", state.conn)
            return
        }

        resumeOffset = try { state.message.data["Offset"]!!.toInt() }
        catch (e: Exception) {
            ServerResponse.sendBadRequest("Invalid value for field Offset", state.conn)
            return
        }
        if (resumeOffset!! < 1 || resumeOffset > fileSize) {
            ServerResponse.sendBadRequest("Invalid value for field Offset", state.conn)
            return
        }
    } else resumeOffset = null

    val config = ServerConfig.get()
    if (fileSize > config.getInteger("performance.max_file_size")!! * 0x10_000) {
        ServerResponse(414, "LIMIT REACHED",
            "File size greater than max allowed on server")
            .sendCatching(state.conn, "Client requested file larger than configured max")
        return
    }

    // Arguments have been validated, do a quota check

    val db = DBConn()
    val quotaInfo = getQuotaInfo(db, state.wid!!).getOrElse {
        logError("Error getting quota for wid ${state.wid!!}: $it")
        ServerResponse.sendInternalError("Server error getting account quota info", state.conn)
        return
    }

    if (quotaInfo.second > 0 && quotaInfo.first > quotaInfo.second) {
        ServerResponse(409, "QUOTA INSUFFICIENT",
            "Your account lacks sufficient space for the file")
            .sendCatching(state.conn, "Client requested file larger than free space")
        return
    }

    val tempPath = if (resumeOffset != null) {
        MServerPath.fromString("/ tmp ${state.wid!!} ${state.message.data["TempName"]!!}")!!
    } else {
        val tempName =
            "${Instant.now().epochSecond}.$fileSize.${UUID.randomUUID().toString().lowercase()}"
        MServerPath.fromString("/ tmp ${state.wid!!} $tempName")!!
    }
    val tempHandle = lfs.entry(tempPath)
    readFileData(state, tempHandle, resumeOffset)?.let {
        // Transfer was interrupted. We won't delete the file--we will leave it so the client can
        // attempt to resume the upload later.
        return
    }

    val serverHash = tempHandle.hashFile(clientHash.prefix).getOrElse {
        if (it is UnsupportedAlgorithmException) {
            ServerResponse(309, "UNSUPPORTED ALGORITHM",
                "Hash algorithm ${clientHash.prefix} not unsupported")
                .sendCatching(state.conn, "Client requested unsupported hash algorithm")
        } else {
            logError("commandUpload: Error hashing file: $it")
            ServerResponse.sendInternalError("Server error hashing file", state.conn)
        }
        return
    }

    if (serverHash != clientHash) {
        tempHandle.delete()
        ServerResponse(410, "HASH MISMATCH").sendCatching(state.conn,
            "Hash mismatch on uploaded file")
        return
    }

    // TODO: Install temp file here
    val realName = ""

    if (replacesPath != null) {
        // TODO: Lock and delete file
        // TODO: finish data for update record here
        addUpdateRecord(db, state.wid!!, UpdateRecord(
            RandomID.generate(), UpdateType.Replace, "add replaces path here",
            "some time stamp", state.devid!!
        ))
    } else {
        lfs.modifyQuotaUsage(state.wid!!, fileSize)?.let {
            logError("commandUpload: Error adjusting quota usage: $it")
            ServerResponse.sendInternalError("Server account quota error", state.conn)
            return
        }
        // TODO: finish data for update record here
        addUpdateRecord(db, state.wid!!, UpdateRecord(
            RandomID.generate(), UpdateType.Create, "add create path here",
            "some time stamp", state.devid!!
        ))
    }

    val ok = ServerResponse(200, "OK")
    ok.data["FileName"] = realName
    ok.sendCatching(state.conn,
        "commandUpload: Couldn't send confirmation response for wid = ${state.wid}")
}

/**
 * Reads file data from a client and writes it directly to the file, optionally resuming from a
 * specified file offset.
 */
private fun readFileData(state: ClientSession, handle: LocalFSHandle, offset: Int?): Throwable? {
    TODO("Implement readFileData($state, $handle, $offset)")
}
