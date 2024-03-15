package mensagod.handlers

import keznacl.onFalse
import libkeycard.MAddress
import libkeycard.MissingFieldException
import libmensago.ServerResponse
import mensagod.*
import mensagod.auth.AuthAction
import mensagod.auth.WIDActor
import mensagod.auth.WorkspaceTarget
import mensagod.dbcmds.*
import mensagod.delivery.queueMessageForDelivery

// GETWID(User-ID, Domain="")
fun commandGetWID(state: ClientSession) {

    val schema = Schemas.getWID
    schema.validate(state.message.data) { name, e ->
        val msg = if (e is MissingFieldException)
            "Missing required field $name"
        else
            "Bad value for field $name"
        QuickResponse.sendBadRequest(msg, state.conn)
    } ?: return

    val uid = schema.getUserID("User-ID", state.message.data)!!
    val domain = schema.getDomain("Domain", state.message.data) ?: gServerDomain
    val address = MAddress.fromParts(uid, domain)

    val wid = resolveAddress(DBConn(), address).getOrElse {
        logError("commandGetWID::resolveAddress error: $it")
        QuickResponse.sendInternalError("", state.conn)
        return
    }

    ServerResponse(200, "OK", "", mutableMapOf("Workspace-ID" to wid.toString()))
        .sendCatching(state.conn, "commandGetWID: success message failure")
}

// IDLE(CountUpdates=null)
fun commandIdle(state: ClientSession) {
    val schema = Schemas.idle
    val updateTime = schema.getUnixTime("CountUpdates", state.message.data)
    if (updateTime == null) {
        QuickResponse.sendOK("", state.conn)
        return
    }

    if (!state.requireLogin()) return

    val count = countSyncRecords(DBConn(), state.wid!!, updateTime).getOrElse {
        QuickResponse.sendInternalError("Server error counting updates", state.conn)
        return
    }

    ServerResponse(200, "OK", "", mutableMapOf("UpdateCount" to count.toString()))
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
        logError("commandSend::resolveWID error: $it")
        QuickResponse.sendInternalError("Error getting sender address", state.conn)
        return
    }
    if (sender == null) {
        logError("commandSend::resolveWID couldn't find wid ${state.wid}")
        QuickResponse.sendInternalError("Sender address missing", state.conn)
        return
    }

    val quotaInfo = getQuotaInfo(db, state.wid!!).getOrElse {
        logError("commandSend::getQuotaInfo error: $it")
        QuickResponse.sendInternalError("Error getting quota information", state.conn)
        return
    }

    if (quotaInfo.second != 0L && message.length + quotaInfo.first > quotaInfo.second) {
        ServerResponse(409, "QUOTA INSUFFICIENT", "")
            .sendCatching(state.conn, "Error sending quota insufficient for send(${state.wid})")
        return
    }

    val lfs = LocalFS.get()
    val handle = lfs.makeTempFile(gServerDevID, message.length.toLong()).getOrElse {
        logError("commandSend::makeTempFile error: $it")
        QuickResponse.sendInternalError("Error creating file for message", state.conn)
        return
    }
    handle.getFile()
        .runCatching { writeText(message) }.onFailure {
            logError("commandSend::writeText error: $it")
            QuickResponse.sendInternalError("Error saving message", state.conn)
            return
        }
    handle.moveToOutbox(state.wid!!)?.let {
        logError("commandSend::moveToOutbox error: $it")
        QuickResponse.sendInternalError("Error moving message to delivery outbox", state.conn)
        return
    }
    queueMessageForDelivery(sender, domain, handle.path)
    ServerResponse(200, "OK", "")
        .sendCatching(state.conn, "Failed to send successful SEND response")
}

// SENDLARGE(Size, Hash, Domain, Name=null, Offset=null)
fun commandSendLarge(state: ClientSession) {
    TODO("Implement commandSendLarge($state)")
}

// SETSTATUS(Workspace-ID, Status)
fun commandSetStatus(state: ClientSession) {
    val schema = Schemas.setStatus
    if (!state.requireLogin(schema)) return

    val wid = schema.getRandomID("Workspace-ID", state.message.data)!!
    val status = WorkspaceStatus.fromString(schema.getString("Status", state.message.data)!!)
    if (status == null) {
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
    }
    if (workspace == null) {
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
    )
        .sendCatching(state.conn, "commandUnrecognized message send error")
}

