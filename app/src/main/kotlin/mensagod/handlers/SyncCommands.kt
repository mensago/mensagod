package mensagod.handlers

import libmensago.ServerResponse
import mensagod.ClientSession
import mensagod.dbcmds.getSyncRecords
import mensagod.withDBResult

// GETUPDATES (time)
fun commandGetUpdates(state: ClientSession) {
    val schema = Schemas.getUpdates
    if (!state.requireLogin(schema)) return

    val time = schema.getUnixTime("Time", state.message.data)!!

    val recList = withDBResult { db ->
        getSyncRecords(db, state.wid!!, time).getOrElse {
            state.internalError(
                "commandGetUpdates.getSyncRecords exception: $it",
                "error getting update records"
            )
            db.disconnect()
            return
        }
    }.getOrElse { return }

    val data = mutableMapOf<String, String>()
    data["UpdateCount"] = recList.size.toString()
    recList.forEachIndexed { i, rec -> data["Update$i"] = rec.toString() }
    ServerResponse(200, "OK", "", data)
        .sendCatching(state.conn, "Failed to send update response")
}
