package mensagod.handlers

import keznacl.*
import libkeycard.MissingFieldException
import libkeycard.Timestamp
import libkeycard.UserEntry
import libmensago.*
import mensagod.*
import mensagod.auth.AuthAction
import mensagod.auth.WIDActor
import mensagod.auth.WorkspaceTarget
import mensagod.dbcmds.*
import mensagod.delivery.queueMessageForDelivery
import java.security.GeneralSecurityException
import java.security.SecureRandom


// DEVICE(Deice-ID, Device-Key, Client-Info)
fun commandDevice(state: ClientSession) {
    if (state.loginState != LoginState.AwaitingDeviceID) {
        state.quickResponse(400, "BAD REQUEST", "Session mismatch error")
        return
    }

    val schema = Schemas.device
    schema.validate(state.message.data) { name, e ->
        val msg = if (e is MissingFieldException)
            "Missing required field $name"
        else
            "Bad value for field $name"
        state.quickResponse(400, "BAD REQUEST", msg)
    } ?: return

    val devid = schema.getRandomID("Device-ID", state.message.data)!!
    val devkey = schema.getCryptoString("Device-Key", state.message.data)!!
    val devinfo = schema.getCryptoString("Device-Info", state.message.data)

    val db = DBConn()
    val devstatus = getDeviceStatus(db, state.wid!!, devid).getOrElse {
        state.internalError(
            "commandDevice.getDeviceStatus exception: $it",
            "Server can't get device status"
        )
        db.disconnect()
        return
    }

    when (devstatus) {
        DeviceStatus.Blocked -> {
            state.quickResponse(403, "FORBIDDEN")
            db.disconnect()
            return
        }

        DeviceStatus.Pending -> {
            state.quickResponse(101, "PENDING", "Awaiting device approval")
            db.disconnect()
            return
        }

        DeviceStatus.Registered, DeviceStatus.Approved -> {
            // The device is part of the workspace, so now we issue undergo a challenge-response
            // to ensure that the device really is authorized and the key wasn't stolen by an
            // impostor
            val success = challengeDevice(state, devkey).getOrElse {
                state.internalError(
                    "commandDevice.challengeDevice exception: $it",
                    "Error authenticating client device"
                )
                db.disconnect()
                return
            }

            if (devinfo != null) {
                updateDeviceInfo(db, state.wid!!, devid, devinfo)?.let {
                    state.internalError(
                        "commandDevice.challengeDevice exception: $it",
                        "Error updating device info"
                    )
                    db.disconnect()
                    return
                }
            }

            if (!success) {
                db.disconnect()
                return
            }
        }

        DeviceStatus.NotRegistered -> {
            if (devinfo == null) {
                state.quickResponse(
                    400, "BAD REQUEST",
                    "Device-Info field required for new devices"
                )
                db.disconnect()
                return
            }

            // 1) Check to see if the workspace has any devices registered.
            val devCount = countDevices(db, state.wid!!).getOrElse {
                state.internalError(
                    "commandDevice.countDevices exception: $it",
                    "Error checking device count"
                )
                db.disconnect()
                return
            }

            // 2) If there are multiple devices, push out an approval request and return
            if (devCount > 0) {
                // Feature: LocalDelivery
                // Feature: DeviceManagement

                val recipient = try {
                    val out = resolveWID(db, state.wid!!).getOrElse {
                        state.internalError(
                            "commandDevice.resolveWID exception: $it",
                            "Error resolving workspace ID",
                        )
                        db.disconnect()
                        return
                    }
                    if (out == null) {
                        state.internalError(
                            "commandDevice.resolveWID returned null for wid ${state.wid!!}",
                            "Server error: workspace missing",
                        )
                        db.disconnect()
                        return
                    }
                    out
                } catch (e: Exception) {
                    state.internalError(
                        "commandDevice.resolveWID exception: $e",
                        "Error looking up workspace address",
                    )
                    db.disconnect()
                    return
                }

                val entryList = getRawEntries(db, recipient.id, 0U)
                    .getOrElse {
                        state.internalError(
                            "commandDevice.getEntries exception: $it",
                            "Error looking up user keycard",
                        )
                        db.disconnect()
                        return
                    }
                if (entryList.size < 1) {
                    state.internalError(
                        "commandDevice: no entries for wid ${state.wid}",
                        "User keycard doesn't exist"
                    )
                    db.disconnect()
                    return
                }
                val userEntry = UserEntry.fromString(entryList[0]).getOrElse {
                    state.internalError(
                        "commandDevice: corrupted current entry for ${state.wid}",
                        "User keycard is corrupted"
                    )
                    db.disconnect()
                    return
                }
                val userKey = userEntry.getEncryptionKey("Encryption-Key")
                if (userKey == null) {
                    state.internalError(
                        "commandDevice.getEncryptionKey failure",
                        "Bad encryption key in user keycard",
                    )
                    db.disconnect()
                    return
                }

                val msg = DeviceApprovalMsg(
                    gServerAddress, recipient, state.conn.inetAddress,
                    devinfo
                )
                println("Envelope sealing key: $userKey")
                val sealed = Envelope.seal(userKey, msg).getOrElse {
                    state.internalError(
                        "commandDevice.seal failure: $it",
                        "Failure in encrypting device approval request",
                    )
                    db.disconnect()
                    return
                }.toStringResult().getOrElse {
                    state.internalError(
                        "commandDevice.toStringResult failure: $it",
                        "Failure serializing encrypted message",
                    )
                    db.disconnect()
                    return
                }
                val lfs = LocalFS.get()
                val handle = lfs.makeTempFile(gServerDevID, sealed.length.toLong()).getOrElse {
                    state.internalError(
                        "commandDevice.makeTempFile failure: $it",
                        "Failure creating file for device request",
                    )
                    db.disconnect()
                    return
                }
                handle.getFile().runCatching { writeText(sealed) }.onFailure {
                    state.internalError(
                        "commandDevice.writeText failure: $it",
                        "Failure saving encrypted device request",
                    )
                    db.disconnect()
                    return
                }
                handle.moveToOutbox(gServerDevID)?.let {
                    state.internalError(
                        "commandDevice.moveToOutbox failure: $it",
                        "Failure moving encrypted device request",
                    )
                    db.disconnect()
                    return
                }

                // call queueMessageForDelivery() with delivery info
                queueMessageForDelivery(gServerAddress, recipient.domain, handle.path)
                state.quickResponse(105, "APPROVAL REQUIRED")
                db.disconnect()
                return
            }
            addDevice(db, state.wid!!, devid, devkey, devinfo, DeviceStatus.Registered)?.let {
                state.internalError(
                    "commandDevice.addDevice exception: $it",
                    "Error adding device"
                )
                db.disconnect()
                return
            }
        }
    }

    // If we've gotten this far, the device is approved and we just need to finish setting up
    // connection state and give the device a success response
    val lfs = LocalFS.get()
    val widPath = MServerPath("/ wsp ${state.wid!!}")
    val widHandle = lfs.entry(widPath)
    widHandle.exists().getOrElse {
        state.internalError(
            "commandDevice.exists exception for $widPath: $it",
            "Error checking for workspace root directory",
        )
        db.disconnect()
        return
    }.onFalse {
        lfs.entry(widPath).makeDirectory()?.let {
            state.internalError(
                "commandDevice.makeDirectory exception for $widPath: $it",
                "Error creating workspace root directory",
            )
            db.disconnect()
            return
        }
    }

    state.currentPath = widPath
    state.loginState = LoginState.LoggedIn

    // Feature: LocalDelivery
    // FeatureTODO: Register workspace with message delivery subsystem
    state.devid = devid

    val response = ServerResponse(200, "OK")

    if (devstatus == DeviceStatus.Approved) {
        val infopath = getKeyInfo(db, state.wid!!, devid).getOrElse {
            state.internalError(
                "commandDevice.getKeyInfo error for ${state.wid}: $it",
                "Error finding new device key information",
            )
            state.loginState = LoginState.NoSession
            state.wid = null
            db.disconnect()
            return
        } ?: run {
            state.internalError(
                "commandDevice.getKeyInfo missing for ${state.wid}",
                "Error finding new device key information",
            )
            state.loginState = LoginState.NoSession
            state.wid = null
            db.disconnect()
            return
        }

        val infoHandle = infopath.toHandle()
        val keyInfo = infoHandle.readAll().getOrElse {
            state.internalError(
                "commandDevice.readFile exception for ${state.wid}: $it",
                "Error reading device key information"
            )
            state.loginState = LoginState.NoSession
            state.wid = null
            db.disconnect()
            return
        }.decodeToString()
        response.code = 203
        response.status = "APPROVED"
        response.data["Key-Info"] = keyInfo
    }

    val isAdmin = state.isAdmin().getOrElse {
        state.internalError(
            "commandDevice.isAdmin exception for ${state.wid}: $it",
            "Error checking for admin privileges"
        )
        state.loginState = LoginState.NoSession
        state.wid = null
        db.disconnect()
        return
    }
    response.data["Is-Admin"] = if (isAdmin) "True" else "False"
    response.send(state.conn)?.let {
        state.loginState = LoginState.NoSession
        state.wid = null
        logError("Error sending successful login information")
        db.disconnect()
        return
    }

    updateDeviceLogin(db, state.wid!!, devid)?.let {
        logError("commandDevice.logDeviceLogin exception for ${state.wid}: $it")
    }

    if (devstatus == DeviceStatus.Approved) {
        removeKeyInfo(db, state.wid!!, devid)?.let {
            logError("commandDevice.removeKeyInfo exception for ${state.wid}: $it")
        }
    }
    db.disconnect()
}

// LOGIN(Login-Type,Workspace-ID, Challenge)
fun commandLogin(state: ClientSession) {
    if (state.loginState != LoginState.NoSession) {
        state.quickResponse(400, "BAD REQUEST", "Session state mismatch")
        return
    }

    val schema = Schemas.login
    schema.validate(state.message.data) { name, e ->
        val msg = if (e is MissingFieldException)
            "Missing required field $name"
        else
            "Bad value for field $name"
        state.quickResponse(400, "BAD REQUEST", msg)
    } ?: return

    if (schema.getString("Login-Type", state.message.data) != "PLAIN") {
        state.quickResponse(400, "BAD REQUEST", "Invalid Login-Type")
        return
    }

    val wid = state.getRandomID("Workspace-ID", true)!!
    val challenge = state.getCryptoString("Challenge", true)!!

    val db = DBConn()
    val status = checkWorkspace(db, wid).getOrElse {
        state.internalError(
            "commandLogin.checkWorkspace exception for ${state.wid}: $it",
            "Error checking workspace ID"
        )
        db.disconnect()
        return
    } ?: run {
        state.quickResponse(404, "NOT FOUND")
        db.disconnect()
        return
    }

    when (status) {
        WorkspaceStatus.Active, WorkspaceStatus.Approved -> {
            // This is fine. Everything is fine. 😉
        }

        WorkspaceStatus.Archived -> {
            state.quickResponse(404, "NOT FOUND")
            db.disconnect()
            return
        }

        WorkspaceStatus.Disabled -> {
            state.quickResponse(407, "UNAVAILABLE", "Account disabled")
            db.disconnect()
            return
        }

        WorkspaceStatus.Pending -> {
            state.quickResponse(
                101, "PENDING",
                "Registration awaiting administrator approval"
            )
            db.disconnect()
            return
        }

        WorkspaceStatus.Preregistered -> {
            state.quickResponse(
                416, "PROCESS INCOMPLETE",
                "Workspace requires use of registration code"
            )
            db.disconnect()
            return
        }

        WorkspaceStatus.Suspended -> {
            state.quickResponse(407, "UNAVAILABLE", "Account suspended")
            db.disconnect()
            return
        }

        WorkspaceStatus.Unpaid -> {
            state.quickResponse(406, "PAYMENT REQUIRED")
            db.disconnect()
            return
        }
    }

    // We got this far, so decrypt the challenge and send it to the client
    val orgPair = getEncryptionPair(db).getOrElse {
        state.internalError(
            "commandLogin.getEncryptionPair exception: $it",
            "Server can't process client login challenge",
        )
        db.disconnect()
        return
    }

    val decrypted = orgPair.decrypt(challenge).getOrElse {
        state.quickResponse(
            306, "KEY FAILURE",
            "Client challenge decryption failure"
        )
        db.disconnect()
        return
    }.decodeToString()

    val passInfo = getPasswordInfo(db, wid).getOrElse {
        state.internalError(
            "commandLogin.getPasswordInfo exception: $it",
            "Server error getting password information",
        )
        db.disconnect()
        return
    }
    if (passInfo == null) {
        state.quickResponse(
            404, "RESOURCE NOT FOUND",
            "Password information not found"
        )
        db.disconnect()
        return
    }

    db.disconnect()
    state.wid = wid
    state.loginState = LoginState.AwaitingPassword
    ServerResponse(100, "CONTINUE")
        .attach("Response", decrypted)
        .attach("Password-Algorithm", passInfo.algorithm)
        .attach("Password-Salt", passInfo.salt)
        .attach("Password-Parameters", passInfo.parameters)
        .sendCatching(state.conn, "commandLogin success message send error")
}

// LOGOUT()
fun commandLogout(state: ClientSession) {
    state.loginState = LoginState.NoSession
    state.wid = null

    state.quickResponse(200, "OK")
}

// PASSWORD(Password-Hash)
fun commandPassword(state: ClientSession) {
    if (!state.message.hasField("Password-Hash")) {
        state.quickResponse(400, "BAD REQUEST", "Missing required field Password-Hash")
        return
    }
    if (state.loginState != LoginState.AwaitingPassword) {
        state.quickResponse(400, "BAD REQUEST", "Session state mismatch")
        return
    }

    val match = withDBResult { db ->
        checkPassword(db, state.wid!!, state.message.data["Password-Hash"]!!).getOrElse {
            state.internalError(
                "commandPassword.checkPassword error: $it",
                "Internal error checking password"
            )
            db.disconnect()
            return
        }
    }.getOrElse { state.unavailableError(); return }

    if (!match) {
        val delay = ServerConfig.get().getInteger("security.failure_delay_sec")!!
        Thread.sleep(delay * 1000L)
        ServerResponse(402, "AUTHENTICATION FAILURE").sendCatching(
            state.conn,
            "commandPassword auth fail message send error"
        )
        return
    }

    state.loginState = LoginState.AwaitingDeviceID
    state.quickResponse(100, "CONTINUE")
}

// PASSCODE(Workspace-ID, Reset-Code, Password-Hash, Password-Algorithm, Password-Salt="",
//     Password-Parameters="")
fun commandPassCode(state: ClientSession) {
    val schema = Schemas.passCode
    schema.validate(state.message.data) { name, e ->
        val msg = if (e is MissingFieldException)
            "Missing required field $name"
        else
            "Bad value for field $name"
        state.quickResponse(400, "BAD REQUEST", msg)
    } ?: return

    val wid = schema.getRandomID("Workspace-ID", state.message.data)!!

    // The password field must pass some basic checks for length, but because we will be hashing
    // the thing with Argon2id, even if the client does a dumb thing and submit a cleartext
    // password, there will be a pretty decent baseline of security in place.
    val passHash = schema.getString("Password-Hash", state.message.data)!!
    if (passHash.codePoints().count() !in 16..128) {
        state.quickResponse(400, "BAD REQUEST", "Invalid password hash")
        return
    }

    val passAlgo = schema.getString("Password-Algorithm", state.message.data)!!

    val resetCode = schema.getString("Reset-Code", state.message.data)!!
    if (resetCode.codePoints().count() !in 16..128) {
        state.quickResponse(400, "BAD REQUEST", "Invalid reset code")
        return
    }

    val passSalt = schema.getString("Password-Salt", state.message.data) ?: ""
    val passParams = schema.getString("Password-Parameters", state.message.data) ?: ""

    val db = DBConn()
    checkResetCode(db, wid, resetCode).getOrElse {
        if (it is ExpiredException) {
            state.quickResponse(415, "EXPIRED", "reset code has expired")
            db.disconnect()
            return
        }

        logError("commandPassCode.checkResetCode for $wid: $it")
        state.quickResponse(
            300, "INTERNAL SERVER ERROR",
            "Server error checking reset code"
        )
        db.disconnect()
        return
    }.onFalse {
        state.quickResponse(401, "UNAUTHORIZED")
        db.disconnect()
        return
    }

    val hasher = Argon2idPassword()
    hasher.updateHash(passHash)
    setPassword(db, wid, hasher.hash, passAlgo, passSalt, passParams)?.let {
        logError("commandPassCode.setPassword for $wid: $it")
        state.quickResponse(
            300, "INTERNAL SERVER ERROR",
            "Server error updating password"
        )
        db.disconnect()
        return
    }

    db.disconnect()
    state.quickResponse(200, "OK")
}

// RESETPASSWORD(Workspace-ID, Reset-Code=null, Expires=null)
fun commandResetPassword(state: ClientSession) {
    val schema = Schemas.resetPassword
    state.requireLogin(schema).onFalse { return }

    val targetWID = schema.getRandomID("Workspace-ID", state.message.data)!!

    val workspace = WorkspaceTarget.fromWID(targetWID).getOrElse {
        logError("commandResetPassword.WorkspaceTarget exception: $it")
        state.quickResponse(300, "INTERNAL SERVER ERROR", "Error finding workspace")
        return
    }
    if (workspace == null) {
        state.quickResponse(404, "NOT FOUND")
        return
    }

    workspace.isAuthorized(WIDActor(state.wid!!), AuthAction.Modify)
        .getOrElse {
            logError("commandResetPassword.checkAuth exception: $it")
            state.quickResponse(
                300, "INTERNAL SERVER ERROR",
                "authorization check error"
            )
            return
        }.onFalse {
            state.quickResponse(
                403, "FORBIDDEN",
                "Regular users can't reset passwords"
            )
            return
        }
    val config = ServerConfig.get()
    val resetCode = schema.getString("Reset-Code", state.message.data)
        ?: RegCodeGenerator.getPassphrase(
            config.getInteger("security.diceware_wordcount")!!
        )
    val expires = Timestamp.fromString(schema.getString("Expires", state.message.data))
        ?: Timestamp().plusMinutes(config.getInteger("security.password_reset_min")!!)

    val hasher = Argon2idPassword()
    hasher.updateHash(resetCode)
    withDB { db ->
        resetPassword(db, targetWID, hasher.hash, expires)?.let {
            logError("commandResetPassword.reset exception: $it")
            state.quickResponse(
                300, "INTERNAL SERVER ERROR",
                "Internal error resetting password"
            )
            db.disconnect()
            return
        }
    }.onFalse { return }

    ServerResponse(
        200, "OK", "", mutableMapOf(
            "Reset-Code" to resetCode,
            "Expires" to expires.toString(),
        )
    ).sendCatching(state.conn, "Error sending password reset code")
}

// SETPASSWORD(Password-Hash, NewPassword-Hash, NewPassword-Algorithm, NewPassword-Salt="",
//     NewPassword-Parameters="")
fun commandSetPassword(state: ClientSession) {
    val schema = Schemas.setPassword
    state.requireLogin(schema).onFalse { return }

    val passHash = schema.getString("Password-Hash", state.message.data)!!
    if (passHash.codePoints().count() !in 16..128) {
        state.quickResponse(400, "BAD REQUEST", "Invalid password hash")
        return
    }
    val newHash = schema.getString("NewPassword-Hash", state.message.data)!!
    if (passHash.codePoints().count() !in 16..128) {
        state.quickResponse(400, "BAD REQUEST", "Invalid new password hash")
        return
    }
    val newAlgo = schema.getString("NewPassword-Algorithm", state.message.data)!!
    val newSalt = schema.getString("NewPassword-Salt", state.message.data) ?: ""
    val newParams = schema.getString("NewPassword-Parameters", state.message.data) ?: ""

    val db = DBConn()
    checkPassword(db, state.wid!!, passHash).getOrElse {
        logError("commandSetPassword.checkPassword: error for ${state.wid}: $it")
        state.quickResponse(
            300, "INTERNAL SERVER ERROR",
            "Server error checking password"
        )
        db.disconnect()
        return
    }.onFalse {
        state.quickResponse(401, "UNAUTHORIZED")
        db.disconnect()
        return
    }

    val hasher = Argon2idPassword()
    hasher.updateHash(newHash)
    setPassword(db, state.wid!!, hasher.hash, newAlgo, newSalt, newParams)?.let {
        logError("commandSetPassword.setPassword for ${state.wid}: $it")
        state.quickResponse(
            300, "INTERNAL SERVER ERROR",
            "Server error updating password"
        )
        db.disconnect()
        return
    }

    db.disconnect()
    state.quickResponse(200, "OK")
}

/**
 * Performs a challenge sequence for a client device.
 *
 * @throws UnsupportedAlgorithmException If the server doesn't support the client's device key algorithm
 * @throws CancelException If the client requested cancellation of the command
 * @throws GeneralSecurityException If the underlying encryption library encountered an error
 * @throws kotlinx.serialization.SerializationException message encoding-specific errors
 * @throws IllegalArgumentException if the encoded input does not comply format's specification
 * @throws java.io.IOException if there was a network error
 */
fun challengeDevice(state: ClientSession, devkey: CryptoString): Result<Boolean> {
    // 1) Generate a 32-byte random string of bytes
    // 2) Encode string in base85
    // 3) Encrypt said string, encode in base85, and return it as part of 100 CONTINUE response
    // 4) Wait for response from client and compare response to original base85 string
    // 5) If strings don't match, respond to client with 402 Authentication Failure and return false
    // 6) If strings match respond to client with 200 OK and return true/nil

    val realKey = EncryptionKey.from(devkey).getOrElse { return it.toFailure() }

    val rng = SecureRandom()
    val rawBytes = ByteArray(32)
    rng.nextBytes(rawBytes)
    val challenge = Base85.encode(rawBytes)
    val encrypted = realKey.encrypt(challenge.toByteArray()).getOrElse { return it.toFailure() }
    ServerResponse(
        100, "CONTINUE", "",
        mutableMapOf("Challenge" to encrypted.toString())
    ).send(state.conn)?.let { return it.toFailure() }

    val req = ClientRequest.receive(state.conn.getInputStream())
        .getOrElse { return it.toFailure() }
    if (req.action == "CANCEL") return CancelException().toFailure()

    if (req.action != "DEVICE") {
        state.quickResponse(400, "BAD REQUEST", "Session state mismatch")
        return false.toSuccess()
    }

    val missingField = req.validate(setOf("Device-ID", "Device-Key", "Response"))
    if (missingField != null) {
        state.quickResponse(400, "BAD REQUEST", "Missing required field $missingField")
        return false.toSuccess()
    }
    if (devkey.toString() != req.data["Device-Key"]) {
        state.quickResponse(400, "BAD REQUEST", "Device key mismatch")
        return false.toSuccess()
    }

    return Result.success(challenge == req.data["Response"])
}