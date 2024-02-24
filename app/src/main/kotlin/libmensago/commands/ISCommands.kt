package libmensago.commands

import keznacl.*
import libkeycard.*
import libmensago.*
import java.security.SecureRandom

/** Handles the process to upload a user entry to the server */
fun addEntry(
    conn: MConn, entry: Entry, orgVKey: Verifier, crsPair: SigningPair, prevHash: CryptoString,
): Throwable? {
    // NOTE: adding an entry to the keycard database must be handled carefully -- security and
    // integrity of the keycard chain tree depends on all t's being crossed and all i's being
    // dotted. Don't make changes to this unless you fully understand the process here and have
    // also double-checked your work.

    // Before we start, make sure that the data in the entry passes basic compliance checks. We
    // can't check for full compliance because a user entry which is fully compliant has all the
    // signatures that this command will add.
    entry.isDataCompliant()?.let { return it }

    // The first round trip to the server provides us with the organization's signature, the hash
    // of the previous entry in the chain tree, and the server's hash of the data we sent. We can't
    // just use the hash of the previous entry in the keycard because the root entry of a user
    // keycard is attached to the chain tree at the latest entry in the organization's keycard. We
    // send the data to the server for the hashes and signature because the server doesn't trust
    // clients any more than the clients trust the server. It provides the hashes and signature, but
    // we verify everything that it gives us.
    val entryText = entry.getFullText("Organization-Signature").getOrElse { return it }
    var req = ClientRequest("ADDENTRY", mutableMapOf("Base-Entry" to entryText))
    conn.send(req)?.let { return it }

    var resp = conn.receive().getOrElse { return it }
    if (resp.code != 100) return ProtocolException(resp.toStatus())

    if (!resp.data.containsKey("Organization-Signature"))
        return SchemaFailureException()

    // Verify the organization's signature and hashes against the data stored locally to ensure that
    // the server didn't change our entry and sign or hash the modified version
    val orgSig = CryptoString.fromString(resp.data["Organization-Signature"]!!).let {
        if (it == null)
            return ServerException(
                "Server exception: bad signature returned (" +
                        "${resp.data["Organization-Signature"]!!})"
            )
        it
    }
    entry.addAuthString("Organization-Signature", orgSig)
    entry.verifySignature("Organization-Signature", orgVKey).let { verResult ->
        val result = verResult.getOrElse { return it }
        if (!result) return SigningFailureException()
    }

    entry.addAuthString("Previous-Hash", prevHash)
    entry.hash()?.let { return it }
    entry.verifyHash().let { verResult ->
        val result = verResult.getOrElse { return it }
        if (!result) return HashMismatchException()
    }

    // Having come this far:
    // 1) The raw entry data has been verified by us
    // 2) The raw entry data has theoretically been verified by the server, digitally signed with
    //    the organization's primary signing key, linked into the keycard chain tree, and hashed.
    // 3) We have also verified that the signature and hash match the data we have locally so that
    //    the server can't have modified our data before signing and hashing

    // Next steps: sign with our key and upload to the server where it verifies everything again
    // before officially adding it to the keycard chain tree.
    entry.sign("User-Signature", crsPair)?.let { return it }
    entry.isCompliant()?.let { return it }

    req = ClientRequest(
        "ADDENTRY", mutableMapOf(
            "User-Signature" to entry.getAuthString("User-Signature")!!.toString(),
            "Previous-Hash" to prevHash.toString(),
            "Hash" to entry.getAuthString("Hash")!!.toString(),
        )
    )
    conn.send(req)?.let { return it }

    resp = conn.receive().getOrElse { return it }

    // Delay needed to prevent sync problems when run on the same box as the server
    Thread.sleep(10)
    if (resp.code != 200) return ProtocolException(resp.toStatus())

    return null
}

/** Returns the session to a state where it is ready for the next command */
fun cancel(conn: MConn): Throwable? {
    val req = ClientRequest("CANCEL")
    conn.send(req)?.let { return it }

    val resp = conn.receive().getOrElse { return it }
    Thread.sleep(10)
    if (resp.code != 200) return ProtocolException(resp.toStatus())

    return null
}

/**
 * Replaces the specified device's key stored on the server. This is used specifically for rotating
 * device keys.
 */
fun devKey(
    conn: MConn, devid: RandomID, oldPair: EncryptionPair,
    newPair: EncryptionPair
): Throwable? {

    var req = ClientRequest(
        "DEVKEY", mutableMapOf(
            "Device-ID" to devid.toString(),
            "Old-Key" to oldPair.publicKey.toString(),
            "New-Key" to newPair.publicKey.toString(),
        )
    )
    conn.send(req)?.let { return it }

    var resp = conn.receive().getOrElse { return it }
    if (resp.code != 100) return ProtocolException(resp.toStatus())

    if (!resp.checkFields(listOf(Pair("Challenge", true))))
        return SchemaFailureException()

    // Both challenges from the server are expected to be Base85-encoded random bytes that are
    // encrypted into a CryptoString. This means we decrypt the challenge and send the resulting
    // decrypted string back to the server as proof of device identity.

    val challStr = CryptoString.fromString(resp.data["Challenge"]!!).let {
        if (it == null)
            return ServerException(
                "Server exception: bad identity challenge received (" +
                        "${resp.data["Challenge"]!!})"
            )
        it
    }
    val challDecrypted = oldPair.decrypt(challStr).getOrElse { return it }.decodeToString()

    val newChallStr = CryptoString.fromString(resp.data["New-Challenge"]!!).let {
        if (it == null)
            return ServerException(
                "Server exception: bad new key challenge received (" +
                        "${resp.data["New-Challenge"]!!})"
            )
        it
    }
    val newChallDecrypted = newPair.decrypt(newChallStr).getOrElse { return it }.decodeToString()

    req = ClientRequest(
        "DEVKEY", mutableMapOf(
            "Device-ID" to devid.toString(),
            "Response" to challDecrypted,
            "New-Response" to newChallDecrypted,
        )
    )
    conn.send(req)?.let { return it }

    resp = conn.receive().getOrElse { return it }
    Thread.sleep(10)
    return if (resp.code != 200) ProtocolException(resp.toStatus()) else null
}

/**
 * Completes the login process by submitting the device ID and responding to the server's device
 * challenge. The call returns true if the user has admin privileges or false if not.
 */
fun device(conn: MConn, info: DeviceInfo): Result<Boolean> {

    if (info.encryptedInfo == null)
        return Result.failure(EmptyDataException("Missing encrypted device info"))

    var req = ClientRequest(
        "DEVICE", mutableMapOf(
            "Device-ID" to info.id.toString(),
            "Device-Key" to info.keypair.publicKey.toString(),
            "Device-Info" to info.encryptedInfo!!.toString(),
        )
    )
    conn.send(req).let { if (it != null) return Result.failure(it) }

    var resp = conn.receive().getOrElse { return Result.failure(it) }
    if (resp.code != 100) return Result.failure(ProtocolException(resp.toStatus()))

    if (!resp.checkFields(listOf(Pair("Challenge", true))))
        return Result.failure(SchemaFailureException())

    // The challenge from the server is expected to be Base85-encoded random bytes that are
    // encrypted into a CryptoString. This means we decrypt the challenge and send the resulting
    // decrypted string back to the server as proof of device identity.

    val challStr = CryptoString.fromString(resp.data["Challenge"]!!).let {
        if (it == null)
            return Result.failure(
                ServerException(
                    "Server exception: bad device challenge received (" +
                            "${resp.data["Challenge"]!!})"
                )
            )
        it
    }
    val challDecrypted =
        info.keypair.decrypt(challStr).getOrElse { return Result.failure(it) }.decodeToString()

    req = ClientRequest(
        "DEVICE", mutableMapOf(
            "Device-ID" to info.id.toString(),
            "Device-Key" to info.keypair.publicKey.toString(),
            "Device-Info" to info.encryptedInfo!!.toString(),
            "Response" to challDecrypted,
        )
    )
    conn.send(req).let { if (it != null) return Result.failure(it) }

    resp = conn.receive().getOrElse { return Result.failure(it) }
    Thread.sleep(10)
    if (resp.code != 200) return Result.failure(ProtocolException(resp.toStatus()))

    if (!resp.checkFields(listOf(Pair("Is-Admin", true))))
        return Result.failure(SchemaFailureException())

    return Result.success(resp.data["Is-Admin"] == "True")
}

/**
 * Obtains keycard entries for a user or an organization. This command is usually called to get an
 * entire keycard or to get updates to it. The start_index parameter refers to the Index field in
 * the keycard entry. To obtain the entire keycard, use an index of 1. To obtain only the current
 * entry, use an index of 0. Specifying another value will result in the server returning all
 * entries from the specified index through the current one. If an index which is out of range is
 * specified, the server will return 404 NOT FOUND. Pass null or an empty string for the owner
 * parameter to get the keycard for an organization.
 */
fun getCard(conn: MConn, owner: String?, startIndex: Long): Result<Keycard> {
    val req = ClientRequest("GETCARD", mutableMapOf("Start-Index" to startIndex.toString()))
    if (!owner.isNullOrEmpty()) {
        if (RandomID.fromString(owner) == null && WAddress.fromString(owner) == null &&
            MAddress.fromString(owner) == null
        )
            return Result.failure(BadValueException("Bad owner value"))
        req.data["Owner"] = owner
    }

    conn.send(req).let { if (it != null) return Result.failure(it) }

    var resp = conn.receive().getOrElse { return Result.failure(it) }
    Thread.sleep(10)
    if (resp.code != 104) return Result.failure(ProtocolException(resp.toStatus()))

    if (!resp.checkFields(listOf(Pair("Total-Size", true), Pair("Item-Count", true))))
        return Result.failure(SchemaFailureException())

    // Although we check to ensure that the server sticks to the spec for the fields in the
    // response, this client library is intended for desktops and mobile devices, so even a card
    // which is a few hundred KB is no big deal.

    // Send an empty TRANSFER request to confirm that we are ready to accept the card data
    conn.send(ClientRequest("TRANSFER"))

    resp = conn.receive().getOrElse { return Result.failure(it) }
    Thread.sleep(10)
    if (resp.code != 200) return Result.failure(ProtocolException(resp.toStatus()))

    if (!resp.checkFields(
            listOf(
                Pair("Total-Size", true),
                Pair("Item-Count", true),
                Pair("Card-Data", true),
            )
        )
    )
        return Result.failure(SchemaFailureException())

    return Keycard.fromString(resp.data["Card-Data"]!!)
}

/**
 * Looks up a workspace ID based on the specified user ID and optional domain. If the domain is
 * not specified, the organization's domain is used.
 */
fun getWID(conn: MConn, uid: UserID, domain: Domain?): Result<RandomID> {

    val req = ClientRequest("GETWID", mutableMapOf("User-ID" to uid.toString()))
    if (domain != null) req.data["Domain"] = domain.toString()
    conn.send(req)?.let { return Result.failure(it) }

    val resp = conn.receive().getOrElse { return Result.failure(it) }
    Thread.sleep(10)
    if (resp.code != 200) return Result.failure(ProtocolException(resp.toStatus()))

    if (!resp.data.containsKey("Workspace-ID")) return Result.failure(SchemaFailureException())
    val out = RandomID.fromString(resp.data["Workspace-ID"]!!)
        ?: return Result.failure(BadValueException("Server exception: bad workspace ID received"))

    return Result.success(out)
}

/**
 * Finds out if an entry index is current. If workspace ID is omitted, this command checks the
 * index for the organization's keycard.
 */
fun isCurrent(conn: MConn, index: Long, wid: RandomID?): Result<Boolean> {

    val req = ClientRequest("ISCURRENT", mutableMapOf("Index" to index.toString()))
    if (wid != null) req.data["Workspace-ID"] = wid.toString()
    conn.send(req)?.let { return Result.failure(it) }

    val resp = conn.receive().getOrElse { return Result.failure(it) }
    Thread.sleep(10)
    if (resp.code != 200) return Result.failure(ProtocolException(resp.toStatus()))

    if (!resp.data.containsKey("Is-Current")) return Result.failure(SchemaFailureException())

    return Result.success(resp.data["Is-Current"]!! == "YES")
}

/** Starts the login process by submitting the desired workspace ID */
fun login(conn: MConn, wid: RandomID, serverKey: Encryptor): Result<PasswordInfo> {

    // We have a challenge for the server to ensure that we're connecting to the server we *think*
    // we are. This is because of an upcoming DANE-like feature which permits self-signed TLS certs.

    val rng = SecureRandom()
    val rawBytes = ByteArray(32)
    rng.nextBytes(rawBytes)
    val challenge = Base85.encode(rawBytes)
    val encrypted = serverKey.encrypt(challenge.toByteArray())
        .getOrElse { return Result.failure(it) }

    val req = ClientRequest(
        "LOGIN", mutableMapOf(
            "Workspace-ID" to wid.toString(),
            "Login-Type" to "PLAIN",
            "Challenge" to encrypted.toString(),
        )
    )
    conn.send(req)?.let { return Result.failure(it) }

    val resp = conn.receive().getOrElse { return Result.failure(it) }
    Thread.sleep(10)
    if (resp.code != 100) return Result.failure(ProtocolException(resp.toStatus()))

    if (!resp.checkFields(listOf(Pair("Response", true), Pair("Password-Algorithm", true))))
        return Result.failure(SchemaFailureException())

    val pwInfo = PasswordInfo(
        resp.data["Password-Algorithm"]!!,
        resp.data["Password-Salt"] ?: "",
        resp.data["Password-Parameters"] ?: "",
    )
    validatePasswordInfo(pwInfo)?.let { return Result.failure(it) }

    return if (resp.data["Response"] == challenge) Result.success(pwInfo)
    else Result.failure(ServerAuthException())
}

/** Logs the current user out without disconnecting */
fun logout(conn: MConn): Throwable? {
    val req = ClientRequest("LOGOUT")
    conn.send(req)?.let { return it }

    val resp = conn.receive().getOrElse { return it }
    Thread.sleep(10)
    return if (resp.code == 200) null else ProtocolException(resp.toStatus())
}

/**
 * Allows a user to set a new password on their workspace given a registration code from an
 * administrator. The process for the user is meant to work exactly the same as setting up a
 * preregistered account.
 */
fun passCode(conn: MConn, wid: RandomID, resetCode: String, pw: Password): Throwable? {

    if (pw.hash.isEmpty()) return EmptyDataException()
    val codeLength = resetCode.codePoints().count()
    if (codeLength < 8 || codeLength > 128) return RangeException()

    val req = ClientRequest(
        "PASSCODE", mutableMapOf(
            "Workspace-ID" to wid.toString(),
            "Reset-Code" to resetCode,
            "Password-Hash" to pw.hash,
            "Password-Algorithm" to pw.algorithm,
        )
    )
    conn.send(req)?.let { return it }

    val resp = conn.receive().getOrElse { return it }
    Thread.sleep(10)
    return if (resp.code == 200) null else ProtocolException(resp.toStatus())
}

/** Continues the login process by sending a password hash for the workspace. */
fun password(conn: MConn, pw: Password, pwinfo: PasswordInfo): Throwable? {

    if (pw.hash.isEmpty()) return EmptyDataException()

    val req = ClientRequest(
        "PASSWORD", mutableMapOf(
            "Password-Hash" to pw.hash,
            "Password-Algorithm" to pwinfo.algorithm
        )
    )
    if (pwinfo.salt.isNotEmpty()) req.data["Password-Salt"] = pwinfo.salt
    if (pwinfo.parameters.isNotEmpty()) req.data["Password-Parameters"] = pwinfo.parameters
    conn.send(req)?.let { return it }

    val resp = conn.receive().getOrElse { return it }
    Thread.sleep(10)
    return if (resp.code == 100) null else ProtocolException(resp.toStatus())
}

/**
 * The PreregInfo structure is to pass around account preregistration information, particularly
 * from the Client class' preregister() method.
 */
data class PreregInfo(var wid: RandomID, var domain: Domain, var uid: UserID?, var regcode: String)

/**
 * Provisions a preregistered account on the server. Note that the uid, wid, and domain are all
 * optional. If none of them are specified, then the server generates an anonymous workspace with
 * the organization's default domain. This command requires administrator privileges.
 */
fun preregister(
    conn: MConn, wid: RandomID?, uid: UserID?,
    domain: Domain?
): Result<PreregInfo> {

    val req = ClientRequest("PREREG")
    if (wid != null) req.data["Workspace-ID"] = wid.toString()
    if (domain != null) req.data["Domain"] = domain.toString()
    if (uid != null) req.data["User-ID"] = uid.toString()

    conn.send(req).let { if (it != null) return Result.failure(it) }

    val resp = conn.receive().getOrElse { return Result.failure(it) }
    Thread.sleep(10)
    if (resp.code != 200) return Result.failure(ProtocolException(resp.toStatus()))

    if (!resp.checkFields(
            listOf(
                Pair("Workspace-ID", true), Pair("Reg-Code", true),
                Pair("Domain", true)
            )
        )
    )
        return Result.failure(SchemaFailureException())

    val outWID = RandomID.fromString(resp.data["Workspace-ID"]!!) ?: return Result.failure(
        ServerException("Server returned bad workspace ID")
    )

    val outUID = UserID.fromString(resp.data["User-ID"])

    val outDom = Domain.fromString(resp.data["Domain"]!!)
        ?: return Result.failure(ServerException("Server returned bad domain"))

    return Result.success(PreregInfo(outWID, outDom, outUID, resp.data["Reg-Code"]!!))
}

/** Requests a graceful disconnect from the server */
fun quit(conn: MConn): Throwable? {

    return conn.send(ClientRequest("QUIT"))
}

/**
 * The RegInfo structure is to pass around account registration information, particularly
 * from the Client class' register() method.
 *
 * @param wid: The user's workspace ID
 * @param devid: The RandomID assigned to this device
 * @param domain: The domain for the account
 * @param uid: The user ID for the account
 * @param pwhash: The hash of the user's password string
 * @param devPair: The asymmetric encryption keypair unique to the device
 */
data class RegInfo(
    var wid: RandomID,
    var devid: RandomID,
    var domain: Domain,
    var uid: UserID?,
    var pwhash: Password,
    var devPair: EncryptionPair
)

/**
 * Finishes the registration of a workspace. The address may be a regular Mensago address or it
 * can be a workspace address.
 */
fun regCode(conn: MConn, address: MAddress, regCode: String, pw: Password, devInfo: DeviceInfo):
        Result<RegInfo> {

    val regCodeData = mutableMapOf(
        "Reg-Code" to regCode,
        "Password-Hash" to pw.hash,
        "Password-Algorithm" to pw.algorithm,
        "Device-ID" to devInfo.id.toString(),
        "Device-Key" to devInfo.keypair.publicKey.toString(),
        "Domain" to address.domain.toString(),
        "Device-Info" to devInfo.encryptedInfo.toString(),
    )
    if (pw.salt.isNotEmpty()) regCodeData["Password-Salt"] = pw.salt
    if (pw.parameters.isNotEmpty()) regCodeData["Password-Parameters"] = pw.parameters
    val req = ClientRequest("REGCODE", regCodeData)

    if (address.userid.type == IDType.WorkspaceID)
        req.data["Workspace-ID"] = address.userid.toString()
    else
        req.data["User-ID"] = address.userid.toString()
    conn.send(req).let { if (it != null) return Result.failure(it) }

    val resp = conn.receive().getOrElse { return Result.failure(it) }
    Thread.sleep(10)
    if (resp.code != 201) return Result.failure(ProtocolException(resp.toStatus()))

    if (!resp.checkFields(
            listOf(
                Pair("Workspace-ID", true), Pair("User-ID", true),
                Pair("Domain", true)
            )
        )
    )
        return Result.failure(SchemaFailureException())

    return Result.success(
        RegInfo(
            RandomID.fromString(resp.data["Workspace-ID"]!!)
                ?: return Result.failure(ServerException("Server returned bad workspace ID")),
            devInfo.id,
            Domain.fromString(resp.data["Domain"]!!)
                ?: return Result.failure(ServerException("Server returned bad domain")),
            UserID.fromString(resp.data["User-ID"]!!)
                ?: return Result.failure(ServerException("Server returned bad user ID")),
            pw,
            devInfo.keypair
        )
    )
}

/**
 * Creates an account on the server. The response received depends on a number of factors,
 * including the registration mode of the server. Upon success, this function will return at least
 * 3 string fields: "wid", "devid", and "domain". If a user ID was supplied, it will also be
 * returned in the field "uid".
 */
fun register(
    conn: MConn, uid: UserID?, pw: Password, devid: RandomID,
    devPair: EncryptionPair, devInfo: CryptoString
): Result<RegInfo> {

    // This construct is a little strange, but it exists to work around the minute possibility that
    // there is a WID collision, i.e. the WID generated by the client already exists on the server.
    // In such an event, it should try again. However, in the ridiculously small chance that the
    // client keeps generating collisions, it should wait 3 seconds after each collision to reduce
    // server load.
    for (tries in 0 until 10) {
        if (tries > 0)
            Thread.sleep(3000)

        // Technically the active profile already has a WID, but it is not attached to a domain and
        // doesn't matter as a result. Rather than adding complexity, we just generate a new UUID
        // and always return the replacement value.
        val testWID = RandomID.generate()
        val regData = mutableMapOf(
            "Workspace-ID" to testWID.toString(),
            "Password-Hash" to pw.hash,
            "Password-Algorithm" to pw.algorithm,
            "Device-ID" to devid.toString(),
            "Device-Key" to devPair.publicKey.toString(),
            "Device-Info" to devInfo.toString(),
        )
        if (pw.salt.isNotEmpty()) regData["Password-Salt"] = pw.salt
        if (pw.parameters.isNotEmpty()) regData["Password-Parameters"] = pw.parameters
        if (uid != null) regData["User-ID"] = uid.toString()
        val req = ClientRequest("REGISTER", regData)

        conn.send(req).let { if (it != null) return Result.failure(it) }

        val resp = conn.receive().getOrElse { return Result.failure(it) }
        Thread.sleep(10)
        when (resp.code) {
            101, 201 -> {
                // Success
                if (!resp.data.containsKey("Domain"))
                    return Result.failure(SchemaFailureException())
                val domain = Domain.fromString(resp.data["Domain"]!!) ?: return Result.failure(
                    ServerException("Server returned bad domain")
                )

                return Result.success(RegInfo(testWID, devid, domain, uid, pw, devPair))
            }

            408 -> {
                // UID or WID exists
                if (!resp.data.containsKey("Field"))
                    return Result.failure(SchemaFailureException())

                when (resp.data["Field"]!!) {
                    "User-ID" -> return Result.failure(ResourceExistsException())
                    "Workspace-ID" -> {
                        // Continue through to next iteration. This case will happen extremely
                        // rarely, if ever -- the randomly-generated workspace ID exists on the
                        // server.
                    }

                    else -> {
                        return Result.failure(
                            ServerException(
                                "Bad Field value in 408 error code from server"
                            )
                        )
                    }
                }
            }

            else -> return Result.failure(ProtocolException(resp.toStatus()))
        }
    } // end for loop

    return Result.failure(ServerException("Can't find a free workspace ID"))
}

/**
 * Unlike setPassword(), this is an administrator command to reset the password for a user account.
 * The `resetCode` and `expires` parameters are completely optional and exist only to give the
 * administrator the option of choosing the reset code and expiration time. If omitted, the server
 * will generate a secure reset code that will expire in the default period of time configured.
 *
 * The timestamp must be at least 10 minutes and no more than 48 hours after the current time on the
 * server. The reset code must be at least 8 and no more than 128 Unicode code points.
 */
fun resetPassword(
    conn: MConn, wid: RandomID, resetCode: String?,
    expires: Timestamp?
): Result<Pair<String, String>> {
    if (!resetCode.isNullOrEmpty()) {
        val codeLength = resetCode.codePoints().count()
        if (codeLength < 8 || codeLength > 128) return Result.failure(RangeException())
    }
    if (expires != null) {
        val now = Timestamp()
        if (expires.isBefore(now.plusMinutes(10)) || expires.isAfter(now.plusHours(48)))
            return Result.failure(RangeException())
    }

    val req = ClientRequest("RESETPASSWORD", mutableMapOf("Workspace-ID" to wid.toString()))

    if (!resetCode.isNullOrEmpty()) req.data["Reset-Code"] = resetCode
    if (expires != null) req.data["Timestamp"] = expires.toString()
    conn.send(req).let { if (it != null) return Result.failure(it) }

    val resp = conn.receive().getOrElse { return Result.failure(it) }
    Thread.sleep(10)
    if (resp.code != 200) return Result.failure(ProtocolException(resp.toStatus()))
    if (!resp.checkFields(listOf(Pair("Expires", true), Pair("Reset-Code", true))))
        return Result.failure(SchemaFailureException())

    return Result.success(Pair(resp.data["Reset-Code"]!!, resp.data["Expires"]!!))
}

/**
 * Allows a user to change their workspace's password. For administrator-assisted password resets,
 * use resetpassword().
 */
fun setPassword(conn: MConn, oldpw: Password, newpw: Password): Throwable? {

    val reqData = mutableMapOf(
        "Password-Hash" to oldpw.hash,
        "NewPassword-Hash" to newpw.hash,
        "NewPassword-Algorithm" to newpw.algorithm,
    )
    if (newpw.salt.isNotEmpty()) reqData["NewPassword-Salt"] = oldpw.salt
    if (newpw.parameters.isNotEmpty()) reqData["NewPassword-Parameters"] = oldpw.parameters

    val req = ClientRequest("SETPASSWORD", reqData)
    conn.send(req)?.let { return it }

    val resp = conn.receive().getOrElse { return it }
    Thread.sleep(10)
    return if (resp.code == 200) return null else ProtocolException(resp.toStatus())
}

/**
 * Sets the activity status of the workspace specified. Requires admin privileges. Currently the
 * status may be 'active', 'disabled', 'suspended', 'unpaid', or 'approved', the last of which is
 * used only for moderated registration.
 */
fun setStatus(conn: MConn, wid: RandomID, status: String): Throwable? {
    if (!listOf("active", "disabled", "suspended", "unpaid", "approved").contains(status))
        return BadValueException("bad status value")

    val req = ClientRequest(
        "SETSTATUS", mutableMapOf(
            "Workspace-ID" to wid.toString(),
            "Status" to status,
        )
    )
    conn.send(req)?.let { return it }

    val resp = conn.receive().getOrElse { return it }
    Thread.sleep(10)

    return if (resp.code == 200) return null else ProtocolException(resp.toStatus())
}

/**
 * Deletes the user's account from the connected server. This can be the user's identity account,
 * but it could also be a membership on a shared workspace when that feature is implemented. In
 * the case of servers using private or moderated registration, this command will return either an
 * error or a Pending status.
 */
fun unregister(conn: MConn, pwhash: String, wid: RandomID?): Result<CmdStatus> {

    val req = ClientRequest("UNREGISTER", mutableMapOf("Password-Hash" to pwhash))
    if (wid != null)
        req.data["Workspace-ID"] = wid.toString()
    conn.send(req).let { if (it != null) return Result.failure(it) }

    val resp = conn.receive().getOrElse { return Result.failure(it) }
    Thread.sleep(10)

    // This particular command is very simple: make a request, because the server will return one of
    // of three possible types of responses: success, pending (for private/moderated
    // registration modes), or an error. In all of those cases there isn't anything else to do.
    return Result.success(resp.toStatus())
}
