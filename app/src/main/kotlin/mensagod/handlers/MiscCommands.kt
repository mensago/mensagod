package mensagod.handlers

import keznacl.UnsupportedAlgorithmException
import keznacl.getType
import keznacl.onFalse
import keznacl.toHash
import libkeycard.MAddress
import libkeycard.MissingFieldException
import libmensago.MServerPath
import libmensago.ServerResponse
import mensagod.*
import mensagod.auth.AuthAction
import mensagod.auth.WIDActor
import mensagod.auth.WorkspaceTarget
import mensagod.dbcmds.*
import mensagod.delivery.queueMessageForDelivery
import java.time.Instant
import java.util.*

// GETWID(User-ID, Domain="")
fun commandGetWID(state: ClientSession) {

    val schema = Schemas.getWID
    schema.validate(state.message.data) { name, e ->
        val msg = if (e is MissingFieldException)
            "Missing required field $name"
        else
            "Bad value for field $name"
        state.quickResponse(400, "BAD REQUEST", msg)
    } ?: return

    val uid = schema.getUserID("User-ID", state.message.data)!!
    val domain = schema.getDomain("Domain", state.message.data) ?: gServerDomain
    val address = MAddress.fromParts(uid, domain)

    val wid = resolveAddress(DBConn(), address).getOrElse {
        state.internalError("commandGetWID::resolveAddress error: $it", "")
        return
    } ?: run {
        state.quickResponse(404, "NOT FOUND")
        return
    }

    ServerResponse(200, "OK").attach("Workspace-ID", wid)
        .sendCatching(state.conn, "commandGetWID: success message failure")
}

// IDLE(CountUpdates=null)
fun commandIdle(state: ClientSession) {
    val schema = Schemas.idle
    val updateTime = schema.getUnixTime("CountUpdates", state.message.data)
    if (updateTime == null) {
        state.quickResponse(200, "OK")
        return
    }

    if (!state.requireLogin()) return

    val count = countSyncRecords(DBConn(), state.wid!!, updateTime).getOrElse {
        state.internalError(
            "Error counting updates: $it",
            "Server error counting updates"
        )
        return
    }

    ServerResponse(200, "OK").attach("UpdateCount", count)
        .sendCatching(state.conn, "Error sending idle response for ${state.wid}")
}

// SEND(Message, Domain)
fun commandSend(state: ClientSession) {
    val schema = Schemas.send
    if (!state.requireLogin(schema)) return

    val message = schema.getString("Message", state.message.data)!!
    if (message.length > 25000000) {
        ServerResponse(414, "LIMIT REACHED", "SEND has a limit of 25MB")
            .sendCatching(state.conn, "Failed to send over-limit message for SEND")
        return
    }
    val domain = schema.getDomain("Domain", state.message.data)!!

    val db = DBConn()
    val sender = resolveWID(db, state.wid!!).getOrElse {
        state.internalError(
            "commandSend::resolveWID error: $it",
            "Error getting sender address"
        )
        return
    } ?: run {
        state.internalError(
            "commandSend::resolveWID couldn't find wid ${state.wid}",
            "Sender address missing"
        )
        return
    }

    val quotaInfo = getQuotaInfo(db, state.wid!!).getOrElse {
        state.internalError(
            "commandSend::getQuotaInfo error: $it",
            "Error getting quota information"
        )
        return
    }

    if (quotaInfo.second != 0L && message.length + quotaInfo.first > quotaInfo.second) {
        ServerResponse(409, "QUOTA INSUFFICIENT", "")
            .sendCatching(state.conn, "Error sending quota insufficient for send(${state.wid})")
        return
    }

    val lfs = LocalFS.get()
    val handle = lfs.makeTempFile(gServerDevID, message.length.toLong()).getOrElse {
        state.internalError(
            "commandSend::makeTempFile error: $it",
            "Error creating file for message"
        )
        return
    }
    handle.getFile()
        .runCatching { writeText(message) }.onFailure {
            state.internalError(
                "commandSend::writeText error: $it",
                "Error saving message"
            )
            return
        }
    handle.moveToOutbox(state.wid!!)?.let {
        state.internalError(
            "commandSend::moveToOutbox error: $it",
            "Error moving message to delivery outbox"
        )
        return
    }
    queueMessageForDelivery(sender, domain, handle.path)
    ServerResponse(200, "OK")
        .sendCatching(state.conn, "Failed to send successful SEND response")
}

// SENDLARGE(Size, Hash, Domain, Name=null, Offset=null)
fun commandSendLarge(state: ClientSession) {
    val schema = Schemas.sendLarge
    if (!state.requireLogin(schema)) return

    val domain = schema.getDomain("Domain", state.message.data)!!
    val sender = resolveWID(DBConn(), state.wid!!).getOrElse {
        state.internalError(
            "Error resolving address for wid ${state.wid}",
            "Error getting sender address for workspace id"
        )
        return
    } ?: run {
        state.internalError(
            "Logged in wid ${state.wid} is non-resolvable",
            "Server workspace ID state error"
        )
        return
    }

    val clientHash = schema.getCryptoString("Hash", state.message.data)!!.toHash() ?: run {
        state.quickResponse(400, "BAD REQUEST", "Invalid Hash field")
        return
    }

    // Both TempName and Offset must be present when resuming
    var tempName = schema.getString("TempName", state.message.data)
    if (tempName != null && !MServerPath.checkFileName(tempName)) {
        state.quickResponse(400, "BAD REQUEST", "Invalid TempName field ")
        return
    }
    val resumeOffset = schema.getLong("Offset", state.message.data)
    if ((tempName == null && resumeOffset != null) || (tempName != null && resumeOffset == null)) {
        state.quickResponse(
            400, "BAD REQUEST",
            "SendLarge resume requires both TempName and Offset fields",
        )
        return
    }

    val fileSize = schema.getLong("Size", state.message.data)!!

    val config = ServerConfig.get()
    val sizeLimit = config.getInteger("performance.max_message_size")!! * 0x100_000
    if (fileSize > sizeLimit) {
        state.quickResponse(414, "LIMIT REACHED")
        return
    }

    // This works because if resumeOffset == null, tempName must also be null at this point. We're
    // given a temporary name by the client only when resuming. Being that we have to have a name
    // for the temporary file, we create one here.
    if (resumeOffset == null)
        tempName =
            "${Instant.now().epochSecond}.$fileSize.${UUID.randomUUID().toString().lowercase()}"

    ServerResponse(100, "CONTINUE")
        .attach("TempName", tempName!!)
        .sendCatching(
            state.conn,
            "commandSendLarge: Error sending continue message for wid ${state.wid!!}"
        ).onFalse { return }

    val tempHandle = MServerPath.fromString("/ tmp ${state.wid!!} $tempName")!!.toHandle()
    state.readFileData(fileSize, tempHandle, resumeOffset)?.let {
        // Transfer was interrupted. We won't delete the file--we will leave it so the client can
        // attempt to resume the upload later.
        ServerResponse(305, "INTERRUPTED", "Interruption source: $it")
            .sendCatching(state.conn, "Send interrupted for wid ${state.wid}")
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
                "commandSendLarge: Error hashing message file: $it",
                "Server error hashing message file"
            )
        }
        return
    }

    if (serverHash != clientHash) {
        tempHandle.delete()?.let {
            logError("commandSendLarge: Error deleting invalid temp file: $it")
        }
        state.quickResponse(410, "HASH MISMATCH", "Hash mismatch on uploaded file")
        return
    }

    tempHandle.moveToOutbox(state.wid!!)?.let {
        state.internalError(
            "commandSendLarge: Error installing temp file: $it",
            "Server error finishing message upload"
        )
        return
    }
    queueMessageForDelivery(sender, domain, tempHandle.path)

    state.quickResponse(200, "OK")
}

// SETSTATUS(Workspace-ID, Status)
fun commandSetStatus(state: ClientSession) {
    val schema = Schemas.setStatus
    if (!state.requireLogin(schema)) return

    val wid = schema.getRandomID("Workspace-ID", state.message.data)!!
    val status = WorkspaceStatus.fromString(schema.getString("Status", state.message.data)!!)
        ?: run {
            state.quickResponse(
                400,
                "BAD REQUEST",
                "Bad value ${state.message.data["Status"]} for status"
            )
            return
        }

    val workspace = WorkspaceTarget.fromWID(wid).getOrElse {
        logError("commandSetStatus.WorkspaceTarget exception: $it")
        state.quickResponse(300, "INTERNAL SERVER ERROR", "Error finding workspace")
        return
    } ?: run {
        state.quickResponse(404, "NOT FOUND")
        return
    }

    workspace.isAuthorized(WIDActor(state.wid!!), AuthAction.Modify)
        .getOrElse {
            logError("commandSetStatus.checkAuth exception: $it")
            state.quickResponse(
                300, "INTERNAL SERVER ERROR",
                "authorization check error"
            )
            return
        }.onFalse {
            state.quickResponse(
                403, "FORBIDDEN",
                "Regular users can't modify workspace status"
            )
            return
        }

    setWorkspaceStatus(DBConn(), wid, status)?.let {
        logError("commandSetStatus.setWorkspaceStatus exception: $it")
        state.quickResponse(
            300, "INTERNAL SERVER ERROR",
            "error setting workspace status"
        )
        return
    }

    state.quickResponse(200, "OK")
}

/** Command used when the client's command isn't recognized */
fun commandUnrecognized(state: ClientSession) {
    ServerResponse(
        400, "BAD REQUEST",
        "Unrecognized command '${state.message.action}'"
    ).sendCatching(state.conn, "commandUnrecognized message send error")
}
