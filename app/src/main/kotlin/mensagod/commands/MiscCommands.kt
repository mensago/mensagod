package mensagod.commands

import libkeycard.MAddress
import libmensago.ServerResponse
import mensagod.ClientSession
import mensagod.DBConn
import mensagod.dbcmds.resolveAddress
import mensagod.gServerDomain
import mensagod.logError

// GETWID(User-ID, Domain="")
fun commandGetWID(state: ClientSession) {
    if (!state.message.hasField("User-ID")) {
        ServerResponse(400, "BAD REQUEST", "Required field missing")
            .send(state.conn)
    }

    val db = DBConn()
    val uid = state.getUserID("User-ID", true) ?: return
    val domain = state.getDomain("Domain", false, gServerDomain) ?: return
    val address = MAddress.fromParts(uid, domain)

    val wid = try { resolveAddress(db, address) }
    catch (e: Exception) {
        logError("commandGetWID::resolveAddress error: $e")
        ServerResponse.sendInternalError("", state.conn)
    }

    ServerResponse(200, "OK", "", mutableMapOf("Workspace-ID" to wid.toString()))
        .send(state.conn)
}

/** Command used when the client's command isn't recognized */
fun commandUnrecognized(state: ClientSession) {
    ServerResponse(400, "BAD REQUEST",
        "Unrecognized command '${state.message.action}'")
        .send(state.conn)
}
