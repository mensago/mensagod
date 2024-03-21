package mensagod.handlers

import keznacl.*
import libkeycard.*
import libmensago.ClientRequest
import libmensago.ServerResponse
import mensagod.*
import mensagod.dbcmds.*

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
        state.quickResponse(400, "BAD REQUEST", "Missing required field Base-Entry")
        return
    }

    // The User-Signature field can only be part of the message once the AddEntry command has
    // started and the org signature and hashes have been added. If present, it constitutes an
    // out-of-order request
    if (state.message.hasField("User-Signature")) {
        state.quickResponse(400, "BAD REQUEST", "Received out-of-order User-Signature")
        return
    }

    val entry = UserEntry.fromString(state.message.data["Base-Entry"]!!).getOrNull()
    if (entry == null) {
        ServerResponse(411, "BAD KEYCARD DATA", "Couldn't create entry from data")
            .sendCatching(
                state.conn,
                "commandAddEntry: Couldn't send response for bad keycard data, " +
                        "wid = ${state.wid}"
            )
        return
    }

    entry.isDataCompliant()?.let {
        ServerResponse(412, "NONCOMPLIANT KEYCARD DATA", it.message ?: "")
            .sendCatching(
                state.conn,
                "commandAddEntry: Couldn't send response for noncompliant keycard data, " +
                        "wid = ${state.wid}"
            )
        return
    }

    val wid = RandomID.fromString(entry.getFieldString("Workspace-ID"))
    if (wid!! != state.wid) {
        ServerResponse(
            411, "BAD KEYCARD DATA",
            "Entry workspace doesn't match login session"
        ).sendCatching(
            state.conn,
            "commandAddEntry: Couldn't send response for wid mismatch, " +
                    "wid = ${state.wid}"
        )
        return
    }

    val db = DBConn()
    if (entry.hasField("User-ID")) {
        val outUID = UserID.fromString(entry.getFieldString("User-ID")!!.lowercase())
            ?: run {
                state.quickResponse(400, "BAD REQUEST", "Bad User-ID")
                db.disconnect()
                return
            }

        // Admin can't change its user ID
        val specialAddr = MAddress.fromParts(UserID.fromString("admin")!!, gServerDomain)
        val specialWID = resolveAddress(db, specialAddr).getOrElse { e ->
            state.internalError(
                "commandAddEntry.resolveAddress exception: $e",
                "Server error resolving a special address"
            )
            db.disconnect()
            return
        } ?: run {
            state.internalError(
                "commandAddEntry: error resolving address ",
                "Internal error in server error handling"
            )
            db.disconnect()
            return
        }

        if (state.wid == specialWID && outUID.toString() != "admin") {
            ServerResponse(
                411, "BAD KEYCARD DATA",
                "Admin, Support, and Abuse can't change their user IDs"
            ).sendCatching(
                state.conn,
                "commandAddEntry: Couldn't send response for special uid " +
                        "change attempt, wid = ${state.wid}"
            )
            db.disconnect()
            return
        }
    }

    // isDataCompliant performs all of the checks we need to ensure that the data given to us by the
    // client is valid EXCEPT checking the expiration
    entry.isExpired().getOrElse {
        state.quickResponse(400, "BAD REQUEST", "Bad expiration field")
        db.disconnect()
        return
    }.onTrue {
        ServerResponse(412, "NONCOMPLIANT KEYCARD DATA", "Entry is expired")
            .sendCatching(
                state.conn,
                "commandAddEntry: Couldn't send response for expired data, " +
                        "wid = ${state.wid}"
            )
        db.disconnect()
        return
    }

    // Because of the way that the keycard data is validated at time of construction, and
    // isDataCompliant() ensures all required fields are present, this can't be null
    val currentIndex = entry.getFieldInteger("Index")!!

    // Here we check to make sure that the entry submitted is allowed to follow the previous one.
    // This just means the new index == the old index +1 and that the chain of trust verifies
    val tempEntryList = getEntries(db, wid, 0U).getOrElse {
        state.internalError(
            "commandAddEntry.getCurrentEntry exception: $it",
            "Server can't get current keycard entry"
        )
        db.disconnect()
        return
    }

    val prevEntry = if (tempEntryList.size > 0) {
        val prevUserEntry = UserEntry.fromString(tempEntryList[0]).getOrElse {
            state.internalError(
                "commandAddEntry.dbCorruption: bad user entry in db, wid=$wid - $it",
                "Error loading previous keycard entry"
            )
            db.disconnect()
            return
        }

        val prevIndex = prevUserEntry.getFieldInteger("Index") ?: run {
            state.internalError(
                "commandAddEntry.dbCorruption: bad user entry in db, wid=$wid, bad index",
                "Error in previous keycard entry"
            )
            db.disconnect()
            return
        }

        if (currentIndex != prevIndex + 1) {
            ServerResponse(412, "NONCOMPLIANT KEYCARD DATA", "Non-sequential index")
                .sendCatching(
                    state.conn,
                    "commandAddEntry: Couldn't send response for nonsequential keycard index, " +
                            "wid = ${state.wid}"
                )
            db.disconnect()
            return
        }
        prevUserEntry
    } else {
        // We're here because there are no previous entries. The Index field must be one here
        // because the only way that a valid root entry can have an Index greater than one is if
        // it's a revocation root entry. Those are added by the REVOKE command.
        if (currentIndex != 1) {
            ServerResponse(
                412, "NONCOMPLIANT KEYCARD DATA",
                "The index of the first keycard entry must be 1"
            ).sendCatching(
                state.conn,
                "commandAddEntry: Couldn't send response for root entry index != 1, " +
                        "wid = ${state.wid}"
            )
            db.disconnect()
            return
        }

        // This is the user's root entry, so the previous entry needs to be the org's current
        // keycard entry.
        val tempOrgList = getEntries(db, null, 0U).getOrElse {
            state.internalError(
                "commandAddEntry.getCurrentOrgEntry exception: $it",
                "Server can't get current org keycard entry"
            )
            db.disconnect()
            return
        }

        OrgEntry.fromString(tempOrgList[0]).getOrElse {
            state.internalError(
                "commandAddEntry.dbCorruption: bad org entry in db - $it",
                "Error loading current org keycard entry"
            )
            db.disconnect()
            return
        }
    }

    // If we managed to get this far, we can (theoretically) trust the initial data set given to us
    // by the client. Here we sign the data with the organization's signing key and send the
    // signature back to the client
    val pskPair = getPrimarySigningPair(db).getOrElse {
        state.internalError(
            "commandAddEntry.getPrimarySigningKey exception: $it",
            "Server can't get org signing key"
        )
        db.disconnect()
        return
    }
    entry.sign("Organization-Signature", pskPair)?.let {
        state.internalError(
            "commandAddEntry.signEntry, wid=$wid - $it",
            "Error signing user entry"
        )
        db.disconnect()
        return
    }

    ServerResponse(100, "CONTINUE")
        .attach(
            "Organization-Signature",
            entry.getAuthString("Organization-Signature")!!
        ).send(state.conn)?.let {
            state.internalError(
                "commandAddEntry.sendContinue, wid=$wid - $it",
                "Error signing user entry"
            )
            db.disconnect()
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
        db.disconnect()
        return
    }

    if (req.action == "CANCEL") {
        ServerResponse(200, "OK").sendCatching(
            state.conn,
            "commandAddEntry: Error sending Cancel acknowledgement, wid = ${state.wid}"
        )
        db.disconnect()
        return
    }
    if (req.action != "ADDENTRY") {
        state.quickResponse(400, "BAD REQUEST", "Session state mismatch")
        db.disconnect()
        return
    }
    req.validate(setOf("Previous-Hash", "Hash", "User-Signature"))?.let {
        state.quickResponse(400, "BAD REQUEST", "Missing required field $it")
        db.disconnect()
        return
    }

    if (prevEntry.getAuthString("Hash")?.toString() != req.data["Previous-Hash"]) {
        ServerResponse(
            412, "NONCOMPLIANT KEYCARD DATA",
            "Previous-Hash mismatch in new entry"
        ).sendCatching(
            state.conn,
            "commandAddEntry: Couldn't send response for hash verify failure, " +
                    "wid = ${state.wid}"
        )
        db.disconnect()
        return
    }
    entry.addAuthString("Previous-Hash", prevEntry.getAuthString("Hash")!!)

    // We're really, really going to make sure the client doesn't screw things up. We'll actually
    // calculate the hash ourselves using the algorithm that the client used and compare the two.
    val clientHash = CryptoString.fromString(req.data["Hash"]!!) ?: run {
        ServerResponse(
            412, "NONCOMPLIANT KEYCARD DATA",
            "Invalid Hash in new entry"
        ).sendCatching(
            state.conn,
            "commandAddEntry: Couldn't send response for invalid hash field, " +
                    "wid = ${state.wid}"
        )
        db.disconnect()
        return
    }
    if (!isSupportedHash(clientHash.prefix)) {
        ServerResponse(
            412, "ALGORITHM NOT SUPPORTED",
            "This server doesn't support hashing with ${clientHash.prefix}"
        ).sendCatching(
            state.conn,
            "commandAddEntry: Couldn't send response for unsupported hash algorithm, " +
                    "wid = ${state.wid}"
        )
        db.disconnect()
        return
    }
    entry.hash(clientHash.getType()!!)?.let {
        state.internalError(
            "commandAddEntry.hashEntry exception: $it",
            "Server error hashing entry"
        )
        db.disconnect()
        return
    }
    if (entry.getAuthString("Hash")!!.toString() != clientHash.toString()) {
        ServerResponse(
            412, "NONCOMPLIANT KEYCARD DATA",
            "New entry hash mismatch"
        ).sendCatching(
            state.conn,
            "commandAddEntry: Couldn't send response for hash field mismatch, " +
                    "wid = ${state.wid}"
        )
        db.disconnect()
        return
    }

    val userSig = CryptoString.fromString(req.data["User-Signature"]!!) ?: run {
        ServerResponse(
            412, "NONCOMPLIANT KEYCARD DATA",
            "Invalid User-Signature in new entry"
        ).sendCatching(
            state.conn,
            "commandAddEntry: Couldn't send response for invalid user signature, " +
                    "wid = ${state.wid}"
        )
        db.disconnect()
        return
    }
    entry.addAuthString("User-Signature", userSig)?.let {
        state.internalError(
            "commandAddEntry.addUserSig: error adding user signature - $it",
            "Error adding user sig to entry"
        )
        db.disconnect()
        return
    }

    val crKeyStr = entry.getFieldString("Contact-Request-Verification-Key")
        ?: run {
            state.internalError(
                "commandAddEntry.dbCorruption: entry missing CRV Key in db, wid=$wid",
                "Error loading entry verification key"
            )
            db.disconnect()
            return
        }
    val crKeyCS = CryptoString.fromString(crKeyStr)
        ?: run {
            state.internalError(
                "commandAddEntry.dbCorruption: invalid previous CRV Key CS in db, wid=$wid",
                "Invalid previous entry verification key"
            )
            db.disconnect()
            return
        }
    val crKey = VerificationKey.from(crKeyCS).getOrElse {
        state.internalError(
            "commandAddEntry.dbCorruption: error creating previous CRV Key, wid=$wid - $it",
            "Error creating previous entry verification key",
        )
        db.disconnect()
        return
    }

    entry.verifySignature("User-Signature", crKey).getOrElse {
        state.internalError(
            "commandAddEntry.verifyError: error verifying entry, wid=$wid - $it",
            "Error verifying entry"
        )
        db.disconnect()
        return
    }.onFalse {
        ServerResponse(
            413, "INVALID SIGNATURE",
            "User signature verification failure"
        ).sendCatching(
            state.conn,
            "commandAddEntry: Couldn't send response for verify failure, " +
                    "wid = ${state.wid}"
        )
        db.disconnect()
        return
    }

    // Wow. We actually made it! YAY

    addEntry(db, entry)?.let {
        state.internalError(
            "commandAddEntry.addEntry: error adding entry, wid=$wid - $it",
            "Error adding entry"
        )
        db.disconnect()
        return
    }

    db.disconnect()
    ServerResponse(200, "OK").sendCatching(
        state.conn,
        "commandAddEntry: Couldn't send confirmation response for " +
                "wid = ${state.wid}"
    )
}

// GETCARD(Start-Index, Owner="", End-Index=0)
fun commandGetCard(state: ClientSession) {

    if (!state.message.hasField("Start-Index")) {
        state.quickResponse(400, "BAD REQUEST", "Missing required field Start-Index")
        return
    }
    val startIndex = runCatching {
        state.message.data["Start-Index"]!!.toUInt()
    }.getOrElse {
        state.quickResponse(400, "BAD REQUEST", "Bad value for field Start-Index")
        return
    }

    val db = DBConn()
    val owner = if (state.message.hasField("Owner")) {
        // The owner can be a Mensago address, a workspace address, or just a workspace ID, so
        // resolving the owner can get... complicated. We'll go in order of ease of validation.

        val resolved = resolveOwner(db, state.message.data["Owner"]!!).getOrElse {
            state.internalError(
                "commandGetCard: Error resolving owner ${state.message.data["Owner"]}: $it",
                "Error resolving owner"
            )
            db.disconnect()
            return
        } ?: run {
            state.quickResponse(400, "BAD REQUEST", "Bad value for field Owner")
            db.disconnect()
            return
        }
        resolved
    } else null


    val endIndex = if (state.message.hasField("End-Index")) {
        val end = runCatching {
            state.message.data["End-Index"]!!.toUInt()
        }.getOrElse {
            state.quickResponse(400, "BAD REQUEST", "Bad value for field End-Index")
            db.disconnect()
            return
        }
        if (end < startIndex) {
            state.quickResponse(
                400, "BAD REQUEST",
                "Start-Index may not be less than Start-Index"
            )
            db.disconnect()
            return
        }
        end
    } else null

    val entries = getEntries(db, owner, startIndex, endIndex).getOrElse {
        state.internalError(
            "commandGetCard: Error looking up entries: $it",
            "Error looking up entries"
        )
        db.disconnect()
        return
    }
    if (entries.isEmpty()) {
        state.quickResponse(404, "NOT FOUND")
        db.disconnect()
        return
    }

    // 56 is the combined length of the header and footer lines
    val totalSize = entries.fold(0) { acc, item -> acc + item.length + 48 }
    ServerResponse(104, "TRANSFER", "")
        .attach("Item-Count", entries.size.toString())
        .attach("Total-Size", totalSize.toString())
        .sendCatching(state.conn, "commandGetCard: Failed to send entry count")
        .onFalse { return }

    val istream = runCatching { state.conn.getInputStream() }.getOrElse {
        logDebug("commandGetCard: error opening input stream: $it")
        db.disconnect()
        return
    }
    val req = ClientRequest.receive(istream).getOrElse {
        logDebug("commandGetCard: error receiving client confirmation: $it")
        db.disconnect()
        return
    }
    if (req.action == "CANCEL") return
    if (req.action != "TRANSFER") {
        state.quickResponse(400, "BAD REQUEST", "Session mismatch")
        db.disconnect()
        return
    }

    db.disconnect()
    ServerResponse(200, "OK")
        .attach("Card-Data", entries.joinToString("") {
            "----- BEGIN ENTRY -----\r\n$it----- END ENTRY -----\r\n"
        }).sendCatching(
            state.conn,
            "commandGetCard: Failure sending card data to ${state.wid}"
        )
}

fun commandIsCurrent(state: ClientSession) {
    val schema = Schemas.isCurrent
    schema.validate(state.message.data) { name, e ->
        val msg = if (e is MissingFieldException)
            "Missing required field $name"
        else
            "Bad value for field $name"
        state.quickResponse(400, "BAD REQUEST", msg)
    } ?: return

    val index = schema.getInteger("Index", state.message.data)!!.toUInt()
    val wid = schema.getRandomID("Workspace-ID", state.message.data)

    val entries = withDBResult { db ->
        getEntries(db, wid, 0U).getOrElse {
            state.internalError(
                "commandIsCurrent: error getting keycard: $it",
                "Server error checking keycard"
            )
            db.disconnect()
            return
        }
    }.getOrElse { state.unavailableError(); return }

    if (entries.isEmpty()) {
        state.quickResponse(404, "NOT FOUND")
        return
    }
    val entryIndex = if (wid != null) {
        val userEntry = UserEntry.fromString(entries[0]).getOrElse {
            state.internalError(
                "Bad user entry in commandIsCurrent for $wid",
                "Server error reading keycard"
            )
            return
        }
        runCatching {
            userEntry.getFieldInteger("Index")!!.toUInt()
        }.getOrElse {
            state.internalError(
                "Invalid index in commandIsCurrent",
                "Bad data in keycard"
            )
            return
        }
    } else {
        val orgEntry = OrgEntry.fromString(entries[0]).getOrElse {
            state.internalError(
                "Bad org entry in commandIsCurrent",
                "Server error reading keycard"
            )
            return
        }
        runCatching {
            orgEntry.getFieldInteger("Index")!!.toUInt()
        }.getOrElse {
            state.internalError(
                "Invalid index in commandIsCurrent",
                "Bad data in keycard"
            )
            return
        }
    }

    ServerResponse(200, "OK")
        .attach("Is-Current", if (index == entryIndex) "YES" else "NO")
        .sendCatching(state.conn, "Error sending isCurrent response")
}

/**
 * Private method which takes a string and does whatever it takes to return the workspace ID for
 * the supplied owner.
 */
private fun resolveOwner(db: DBConn, owner: String): Result<RandomID?> {
    val wid = RandomID.fromString(owner)
    if (wid != null)
        return wid.toSuccess()

    val waddr = WAddress.fromString(owner)
    if (waddr != null)
        return waddr.id.toSuccess()

    val maddr = MAddress.fromString(owner)
    if (maddr != null) {
        val out = resolveUserID(db, maddr.userid).getOrElse { return it.toFailure() }
        return out.toSuccess()
    }
    return Result.success(null)
}
