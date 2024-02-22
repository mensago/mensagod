package mensagod.handlers

import libkeycard.MAddress
import libmensago.ServerResponse
import mensagod.*
import mensagod.dbcmds.resolveAddress

// GETWID(User-ID, Domain="")
fun commandGetWID(state: ClientSession) {
    if (!state.message.hasField("User-ID")) {
        ServerResponse(400, "BAD REQUEST", "Required field missing")
            .sendCatching(state.conn, "commandGetWID: required field error message failure")
    }

    val db = DBConn()
    val uid = state.getUserID("User-ID", true) ?: return
    val domain = state.getDomain("Domain", false, gServerDomain) ?: return
    val address = MAddress.fromParts(uid, domain)

    val wid = resolveAddress(db, address).getOrElse {
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
