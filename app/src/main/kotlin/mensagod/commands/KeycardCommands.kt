package mensagod.commands

import libkeycard.MAddress
import libkeycard.RandomID
import libkeycard.UserEntry
import libkeycard.UserID
import mensagod.ClientSession
import mensagod.DBConn
import mensagod.dbcmds.resolveAddress
import mensagod.gServerDomain
import mensagod.logError

// ADDENTRY(Base-Entry)
fun commandAddEntry(state: ClientSession) {

    // This is probably the most complicated command in the entire server because so much depends
    // on secure, reliable storage of digital certificates and no one trusts anyone else more than
    // absolutely necessary.

    // 1) Client sends the `ADDENTRY` command, attaching the entry data.
    // 2) The server then checks compliance of the entry data. Assuming that it complies, the server
    //    generates a cryptographic signature and responds with `100 CONTINUE`, returning the
    //    signature, the hash of the data, and the hash of the previous entry in the database.
    // 3) The client verifies the signature against the organization’s verification key. This has
    //    the added benefit of ensuring that none of the fields were altered by the server and that
    //    the signature is valid.
    // 4) The client appends the hash from the previous entry as the `Previous-Hash` field
    // 5) The client verifies the hash value for the entry from the server and sets the `Hash` field
    // 6) The client signs the entry as the `User-Signature` field and then uploads the result to
    //    the server.
    // 7) Once uploaded, the server validates the `Hash` and `User-Signature` fields, and,
    //    assuming that all is well, adds it to the keycard database and returns `200 OK`.

    if (!state.requireLogin()) return

    if (!state.message.hasField("Base-Entry")) {
        ServerResponse.sendBadRequest("Missing required field Base-Entry", state.conn)
        return
    }

    // The User-Signature field can only be part of the message once the AddEntry command has
    // started and the org signature and hashes have been added. If present, it constitutes an
    // out-of-order request
    if (!state.message.hasField("User-Signature")) {
        ServerResponse.sendBadRequest("Received out-of-order User-Signature", state.conn)
        return
    }

    val entry = UserEntry.fromString(state.message.data["Base-Entry"]!!).getOrNull()
    if (entry == null) {
        ServerResponse(411, "BAD KEYCARD DATA", "Couldn't create entry from data")
            .sendCatching(state.conn,
                "commandAddEntry: Couldn't send response for bad keycard data, "+
                        "wid = ${state.wid}")
        return
    }

    entry.isDataCompliant()?.let {
        ServerResponse(412, "NONCOMPLIANT KEYCARD DATA", it.message ?: "")
            .sendCatching(state.conn,
                "commandAddEntry: Couldn't send response for noncompliant keycard data, "+
                        "wid = ${state.wid}")
        return
    }

    val wid = RandomID.fromString(entry.getFieldString("Workspace-ID"))
    if (wid!! != state.wid) {
        ServerResponse(411, "BAD KEYCARD DATA",
            "Entry workspace doesn't match login session")
            .sendCatching(state.conn,
                "commandAddEntry: Couldn't send response for wid mismatch, "+
                        "wid = ${state.wid}")
        return
    }

    val db = DBConn()
    if (entry.hasField("User-ID")) {
        val outUID = UserID.fromString(entry.getFieldString("User-ID")!!.lowercase())
        if (outUID == null) {
            ServerResponse.sendBadRequest("Bad User-ID", state.conn)
            return
        }

        // Admin, support, and abuse can't change their user IDs
        listOf("admin", "support", "abuse").forEach {
            val specialAddr = MAddress.fromParts(UserID.fromString(it)!!, gServerDomain)
            val specialWID = resolveAddress(db, specialAddr)
            if (specialWID == null) {
                logError("commandAddEntry: error resolving address ")
                ServerResponse.sendInternalError("Internal error in server error handling",
                    state.conn)
                return
            }

            if (state.wid == specialWID) {
                ServerResponse(411, "BAD KEYCARD DATA",
                    "Admin, Support, and Abuse can't change their user IDs")
                    .sendCatching(state.conn,
                        "commandAddEntry: Couldn't send response for special uid " +
                                "change attempt, wid = ${state.wid}")
                return
            }
        }
    }

    // isDataCompliant performs all of the checks we need to ensure that the data given to us by the
    // client is valid EXCEPT checking the expiration
    val isExpired = entry.isExpired()
    if (isExpired.isFailure) {
        ServerResponse.sendBadRequest("Bad expiration field", state.conn)
        return
    }
    if (isExpired.getOrThrow()) {
        ServerResponse(412, "NONCOMPLIANT KEYCARD DATA", "Entry is expired")
            .sendCatching(state.conn,
                "commandAddEntry: Couldn't send response for expired data, "+
                        "wid = ${state.wid}")
        return
    }

    // Because of the way that the keycard data is validated at time of construction, and
    // isDataCompliant() ensures all required fields are present, this can't be null
    val currentIndex = entry.getFieldInteger("Index")!!

    // TODO: Finish implementing commandAddEntry(). Depends on getUserEntries()
}
