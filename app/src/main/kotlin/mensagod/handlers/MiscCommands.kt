package mensagod.handlers

import libkeycard.MAddress
import libkeycard.MissingFieldException
import libmensago.ServerResponse
import mensagod.*
import mensagod.dbcmds.getQuotaInfo
import mensagod.dbcmds.resolveAddress
import mensagod.dbcmds.resolveWID
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

/** Command used when the client's command isn't recognized */
fun commandUnrecognized(state: ClientSession) {
    ServerResponse(
        400, "BAD REQUEST",
        "Unrecognized command '${state.message.action}'"
    )
        .sendCatching(state.conn, "commandUnrecognized message send error")
}

// SEND(Message, Domain)
fun commandSend(state: ClientSession) {
    if (!state.requireLogin()) return

    val schema = Schemas.send
    schema.validate(state.message.data) { name, e ->
        val msg = if (e is MissingFieldException)
            "Missing required field $name"
        else
            "Bad value for field $name"
        QuickResponse.sendBadRequest(msg, state.conn)
    } ?: return

    val message = schema.getString("Message", state.message.data)!!
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
