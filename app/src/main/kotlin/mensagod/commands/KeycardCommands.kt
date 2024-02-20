package mensagod.commands

import keznacl.CryptoString
import keznacl.VerificationKey
import keznacl.getSupportedHashAlgorithms
import libkeycard.*
import libmensago.ClientRequest
import libmensago.ServerResponse
import mensagod.*
import mensagod.dbcmds.addEntry
import mensagod.dbcmds.getEntries
import mensagod.dbcmds.getPrimarySigningPair
import mensagod.dbcmds.resolveAddress

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
        QuickResponse.sendBadRequest("Missing required field Base-Entry", state.conn)
        return
    }

    // The User-Signature field can only be part of the message once the AddEntry command has
    // started and the org signature and hashes have been added. If present, it constitutes an
    // out-of-order request
    if (state.message.hasField("User-Signature")) {
        QuickResponse.sendBadRequest("Received out-of-order User-Signature", state.conn)
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
            QuickResponse.sendBadRequest("Bad User-ID", state.conn)
            return
        }

        // Admin, support, and abuse can't change their user IDs
        listOf("admin", "support", "abuse").forEach {
            val specialAddr = MAddress.fromParts(UserID.fromString(it)!!, gServerDomain)
            val specialWID = resolveAddress(db, specialAddr).getOrElse { e ->
                logError("commandAddEntry.resolveAddress exception: $e")
                QuickResponse.sendInternalError("Server error resolving a special address",
                    state.conn)
                return
            }
            if (specialWID == null) {
                logError("commandAddEntry: error resolving address ")
                QuickResponse.sendInternalError("Internal error in server error handling",
                    state.conn)
                return
            }

            if (state.wid == specialWID && outUID.toString() != it) {
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
        QuickResponse.sendBadRequest("Bad expiration field", state.conn)
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

    // Here we check to make sure that the entry submitted is allowed to follow the previous one.
    // This just means the new index == the old index +1 and that the chain of trust verifies
    val tempEntryList = getEntries(db, wid, 0U).getOrElse {
        logError("commandAddEntry.getCurrentEntry exception: $it")
        QuickResponse.sendInternalError("Server can't get current keycard entry", state.conn)
        return
    }

    val prevEntry = if (tempEntryList.size > 0) {
        val prevUserEntry = UserEntry.fromString(tempEntryList[0]).getOrElse {
            logError("commandAddEntry.dbCorruption: bad user entry in db, wid=$wid - $it")
            QuickResponse.sendInternalError("Error loading previous keycard entry", state.conn)
            return
        }

        val prevIndex = prevUserEntry.getFieldInteger("Index")
        if (prevIndex == null) {
            logError("commandAddEntry.dbCorruption: bad user entry in db, wid=$wid, bad index")
            QuickResponse.sendInternalError("Error in previous keycard entry", state.conn)
            return
        }

        if (currentIndex != prevIndex+1) {
           ServerResponse(412, "NONCOMPLIANT KEYCARD DATA", "Non-sequential index")
               .sendCatching(state.conn,
                   "commandAddEntry: Couldn't send response for nonsequential keycard index, "+
                           "wid = ${state.wid}")
           return
        }
        prevUserEntry
    } else {
        // We're here because there are no previous entries. The Index field must be one here
        // because the only way that a valid root entry can have an Index greater than one is if
        // it's a revocation root entry. Those are added by the REVOKE command.
        if (currentIndex != 1) {
            ServerResponse(412, "NONCOMPLIANT KEYCARD DATA",
                "The index of the first keycard entry must be 1")
                .sendCatching(state.conn,
                    "commandAddEntry: Couldn't send response for root entry index != 1, "+
                            "wid = ${state.wid}")
            return
        }

        // This is the user's root entry, so the previous entry needs to be the org's current
        // keycard entry.
        val tempOrgList = getEntries(db, null, 0U).getOrElse {
            logError("commandAddEntry.getCurrentOrgEntry exception: $it")
            QuickResponse.sendInternalError("Server can't get current org keycard entry",
                state.conn)
            return
        }

        OrgEntry.fromString(tempOrgList[0]).getOrElse {
            logError("commandAddEntry.dbCorruption: bad org entry in db - $it")
            QuickResponse.sendInternalError("Error loading current org keycard entry",
                state.conn)
            return
        }
    }

    // If we managed to get this far, we can (theoretically) trust the initial data set given to us
    // by the client. Here we sign the data with the organization's signing key and send the
    // signature back to the client
    val pskPair = getPrimarySigningPair(db).getOrElse {
        logError("commandAddEntry.getPrimarySigningKey exception: $it")
        QuickResponse.sendInternalError("Server can't get org signing key", state.conn)
        return
    }
    entry.sign("Organization-Signature", pskPair)?.let {
        logError("commandAddEntry.signEntry, wid=$wid - $it")
        QuickResponse.sendInternalError("Error signing user entry", state.conn)
        return
    }

    try { ServerResponse(100, "CONTINUE", "", mutableMapOf(
                "Organization-Signature" to entry.getAuthString("Organization-Signature")!!
                    .toString()))
            .send(state.conn)
    } catch (e: Exception) {
        logError("commandAddEntry.sendContinue, wid=$wid - $e")
        QuickResponse.sendInternalError("Error signing user entry", state.conn)
        return
    }

    // ADDENTRY, Stage 2
    // Client has attached the Previous-Hash and Hash fields and then signed the entire thing. We're
    // really close to it being compliant and ready to put into the database, but we need to check
    // the hashes to make sure the client doesn't try anything funny and confirm that the whole
    // thing validates before adding it to the database -- the integrity of the keycard tree is of
    // critical importance to the platform.

    val req = ClientRequest.receive(state.conn.getInputStream()).getOrElse {
        logError("commandAddEntry.receive2ndStage, wid=$wid - $it")
        return
    }

    if (req.action == "CANCEL") {
        ServerResponse(200, "OK").sendCatching(state.conn,
                "commandAddEntry: Error sending Cancel acknowledgement, wid = ${state.wid}")
        return
    }
    if (req.action != "ADDENTRY") {
        QuickResponse.sendBadRequest("Session state mismatch", state.conn)
        return
    }
    req.validate(setOf("Previous-Hash", "Hash", "User-Signature"))?.let {
        QuickResponse.sendBadRequest("Missing required field $it", state.conn)
        return
    }

    if (prevEntry.getAuthString("Hash")?.toString() != req.data["Previous-Hash"]) {
            ServerResponse(412, "NONCOMPLIANT KEYCARD DATA",
            "Previous-Hash mismatch in new entry")
            .sendCatching(state.conn,
                "commandAddEntry: Couldn't send response for hash verify failure, "+
                        "wid = ${state.wid}")
        return
    }
    entry.addAuthString("Previous-Hash", prevEntry.getAuthString("Hash")!!)

    // We're really, really going to make sure the client doesn't screw things up. We'll actually
    // calculate the hash ourselves using the algorithm that the client used and compare the two.
    val clientHash = CryptoString.fromString(req.data["Hash"]!!)
    if (clientHash == null) {
        ServerResponse(412, "NONCOMPLIANT KEYCARD DATA",
            "Invalid Hash in new entry")
            .sendCatching(state.conn,
                "commandAddEntry: Couldn't send response for invalid hash field, "+
                        "wid = ${state.wid}")
        return
    }
    if (!getSupportedHashAlgorithms().contains(clientHash.prefix)) {
        ServerResponse(412, "ALGORITHM NOT SUPPORTED",
            "This server doesn't support hashing with ${clientHash.prefix}")
            .sendCatching(state.conn,
                "commandAddEntry: Couldn't send response for unsupported hash algorithm, "+
                        "wid = ${state.wid}")
        return
    }
    entry.hash(clientHash.prefix)?.let {
        logError("commandAddEntry.hashEntry exception: $it")
        QuickResponse.sendInternalError("Server error hashing entry", state.conn)
        return
    }
    if (entry.getAuthString("Hash")!!.toString() != clientHash.toString()) {
        ServerResponse(412, "NONCOMPLIANT KEYCARD DATA",
            "New entry hash mismatch")
            .sendCatching(state.conn,
                "commandAddEntry: Couldn't send response for hash field mismatch, "+
                        "wid = ${state.wid}")
        return
    }

    val userSig = CryptoString.fromString(req.data["User-Signature"]!!)
    if (userSig == null) {
        ServerResponse(412, "NONCOMPLIANT KEYCARD DATA",
            "Invalid User-Signature in new entry")
            .sendCatching(state.conn,
                "commandAddEntry: Couldn't send response for invalid user signature, "+
                        "wid = ${state.wid}")
        return
    }
    entry.addAuthString("User-Signature", userSig)?.let {
        logError("commandAddEntry.addUserSig: error adding user signature - $it")
        QuickResponse.sendInternalError("Error adding user sig to entry", state.conn)
        return
    }

    val crKeyStr = entry.getFieldString("Contact-Request-Verification-Key")
    if (crKeyStr == null) {
        logError("commandAddEntry.dbCorruption: entry missing CRV Key in db, wid=$wid")
        QuickResponse.sendInternalError("Error loading entry verification key", state.conn)
        return
    }
    val crKeyCS = CryptoString.fromString(crKeyStr)
    if (crKeyCS == null) {
        logError("commandAddEntry.dbCorruption: invalid previous CRV Key CS in db, wid=$wid")
        QuickResponse.sendInternalError("Invalid previous entry verification key", state.conn)
        return
    }
    val crKey = VerificationKey.from(crKeyCS).getOrElse {
        logError("commandAddEntry.dbCorruption: error creating previous CRV Key, "+
                "wid=$wid - $it")
        QuickResponse.sendInternalError("Error creating previous entry verification key",
            state.conn)
        return
    }

    val verified = entry.verifySignature("User-Signature", crKey).getOrElse {
        logError("commandAddEntry.verifyError: error verifying entry, wid=$wid - $it")
        QuickResponse.sendInternalError("Error verifying entry", state.conn)
        return
    }
    if (!verified) {
        ServerResponse(413, "INVALID SIGNATURE","User signature verification failure")
            .sendCatching(state.conn,
                "commandAddEntry: Couldn't send response for verify failure, "+
                        "wid = ${state.wid}")
        return
    }

    // Wow. We actually made it! YAY

    addEntry(db, entry)?.let {
        logError("commandAddEntry.addEntry: error adding entry, wid=$wid - $it")
        QuickResponse.sendInternalError("Error adding entry", state.conn)
        return
    }

    ServerResponse(200, "OK").sendCatching(state.conn,
            "commandAddEntry: Couldn't send confirmation response for "+
                    "wid = ${state.wid}")
}

// GETCARD(Start-Index, Owner="", End-Index=0)
fun commandGetCard(state: ClientSession) {

    if (!state.message.hasField("Start-Index")) {
        QuickResponse.sendBadRequest("Missing required field Start-Index", state.conn)
        return
    }
    val startIndex = try { state.message.data["Start-Index"]!!.toInt() }
    catch (e: Exception) {
        QuickResponse.sendBadRequest("Bad value for field Start-Index", state.conn)
        return
    }
    if (startIndex < 0) {
        QuickResponse.sendBadRequest("Start-Index must be non-negative", state.conn)
        return
    }

    val owner: WAddress?
    if (state.message.hasField("Owner")) {
        // The owner can be a Mensago address, a workspace address, or just a workspace ID, so
        // resolving the owner can get... complicated. We'll go in order of ease of validation.

        val resolved = resolveOwner(state.message.data["Owner"]!!)
        if (resolved == null) {
            QuickResponse.sendBadRequest("Bad value for field Owner", state.conn)
            return
        }
        owner = resolved
    }

    val endIndex: Int?
    if (state.message.hasField("End-Index")) {
        val end = try { state.message.data["End-Index"]!!.toInt() }
        catch (e: Exception) {
            QuickResponse.sendBadRequest("Bad value for field End-Index", state.conn)
            return
        }
        if (end < 0 || end < startIndex) {
            QuickResponse.sendBadRequest("Start-Index must be non-negative and may not be " +
                    "less than Start-Index", state.conn)
            return
        }
        endIndex = end
    }

    // TODO: Finish implementing commandGetCard()
}

private fun resolveOwner(owner: String): WAddress? {
    TODO("Implement resolveOwner($owner)")
}