package mensagod.handlers

import libkeycard.MAddress
import libkeycard.MissingFieldException
import libmensago.ServerResponse
import mensagod.*
import mensagod.dbcmds.resolveAddress

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
