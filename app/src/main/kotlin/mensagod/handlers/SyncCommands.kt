package mensagod.handlers

import libkeycard.MissingFieldException
import libmensago.ServerResponse
import mensagod.ClientSession
import mensagod.DBConn
import mensagod.dbcmds.getSyncRecords

// GETUPDATES (time)
fun commandGetUpdates(state: ClientSession) {
    if (!state.requireLogin()) return

    val schema = Schemas.getUpdates
    schema.validate(state.message.data) { name, e ->
        val msg = if (e is MissingFieldException)
            "Missing required field $name"
        else
            "Bad value for field $name"
        state.quickResponse(400, "BAD REQUEST", msg)
    } ?: return

    val time = schema.getUnixTime("Time", state.message.data)!!

    val db = DBConn()
    val recList = getSyncRecords(db, state.wid!!, time).getOrElse {
        state.internalError(
            "commandGetUpdates.getSyncRecords exception: $it",
            "error getting update records"
        )
        return
    }

    val data = mutableMapOf<String, String>()
    data["UpdateCount"] = recList.size.toString()
    recList.forEachIndexed { i, rec -> data["Update$i"] = rec.toString() }
    ServerResponse(200, "OK", "", data)
        .sendCatching(state.conn, "Failed to send update response")
}
