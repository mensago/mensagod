package mensagod.handlers

import keznacl.*
import libmensago.*
import libmensago.resolver.KCResolver
import mensagod.*
import mensagod.dbcmds.*
import mensagod.delivery.queueMessageForDelivery
import java.security.GeneralSecurityException
import java.security.SecureRandom


// DEVICE(Deice-ID, Device-Key, Client-Info)
fun commandDevice(state: ClientSession) {
    if (state.loginState != LoginState.AwaitingDeviceID) {
        QuickResponse.sendBadRequest("Session mismatch error", state.conn)
        return
    }

    val devid = state.getRandomID("Device-ID", true) ?: return
    val devkey = state.getCryptoString("Device-Key", true) ?: return
    val devinfo = state.getCryptoString("Device-Info", false)

    val db = DBConn()
    val devstatus = getDeviceStatus(db, state.wid!!, devid).getOrElse {
        logError("commandDevice.getDeviceStatus exception: $it")
        QuickResponse.sendInternalError("Server can't get device status", state.conn)
        return
    }

    when (devstatus) {
        DeviceStatus.Blocked -> {
            if (!ServerResponse(403, "FORBIDDEN")
                    .sendCatching(state.conn, "commandDevice.1")
            )
                return
        }

        DeviceStatus.Pending -> {
            if (!ServerResponse(101, "PENDING", "Awaiting device approval")
                    .sendCatching(state.conn, "commandDevice.2")
            )
                return
        }

        DeviceStatus.Registered, DeviceStatus.Approved -> {
            // The device is part of the workspace, so now we issue undergo a challenge-response
            // to ensure that the device really is authorized and the key wasn't stolen by an
            // impostor
            val success = challengeDevice(state, devkey).getOrElse {
                logError("commandDevice.challengeDevice exception: $it")
                QuickResponse.sendInternalError(
                    "Error authenticating client device",
                    state.conn
                )
                return
            }

            if (devinfo != null) {
                updateDeviceInfo(db, state.wid!!, devid, devinfo)?.let {
                    logError("commandDevice.challengeDevice exception: $it")
                    QuickResponse.sendInternalError(
                        "Error updating device info",
                        state.conn
                    )
                    return
                }
            }

            if (!success) return
        }

        DeviceStatus.NotRegistered -> {
            if (devinfo == null) {
                QuickResponse.sendBadRequest(
                    "Device-Info field required for new devices",
                    state.conn
                )
                return
            }

            // 1) Check to see if the workspace has any devices registered.
            val devCount = countDevices(db, state.wid!!).getOrElse {
                logError("commandDevice.countDevices exception: $it")
                QuickResponse.sendInternalError(
                    "Error checking device count",
                    state.conn
                )
                return
            }

            // 2) If there are multiple devices, push out an approval request and return
            if (devCount > 0) {
                // Feature: LocalDelivery
                // Feature: DeviceManagement

                val recipient = try {
                    val out = resolveWID(db, state.wid!!).getOrElse {
                        logError("commandDevice.resolveWID exception: $it")
                        QuickResponse.sendInternalError(
                            "Error resolving workspace ID",
                            state.conn
                        )
                        return
                    }
                    if (out == null) {
                        logError("commandDevice.resolveWID returned null for wid ${state.wid!!}")
                        QuickResponse.sendInternalError(
                            "Server error: workspace missing",
                            state.conn
                        )
                        return
                    }
                    out
                } catch (e: Exception) {
                    logError("commandDevice.resolveWID exception: $e")
                    QuickResponse.sendInternalError(
                        "Error looking up workspace address",
                        state.conn
                    )
                    return
                }

                val userEntry =
                    KCResolver.getCurrentEntry(EntrySubject.fromWAddress(recipient))
                        .getOrElse {
                            logError("commandDevice.getCurrentEntry exception: $it")
                            QuickResponse.sendInternalError(
                                "Error looking up user keycard",
                                state.conn
                            )
                            return
                        }
                val userKey = userEntry.getEncryptionKey("Encryption-Key")
                if (userKey == null) {
                    logError("commandDevice.getEncryptionKey failure")
                    QuickResponse.sendInternalError(
                        "Bad encryption key in user keycard",
                        state.conn
                    )
                    return
                }

                val msg = DeviceApprovalMsg(
                    gServerAddress, recipient, state.conn.inetAddress,
                    devinfo
                )
                val sealed = Envelope.seal(userKey, msg).getOrElse {
                    logError("commandDevice.seal failure: $it")
                    QuickResponse.sendInternalError(
                        "Failure in encrypting device approval request",
                        state.conn
                    )
                    return
                }.toStringResult().getOrElse {
                    logError("commandDevice.toStringResult failure: $it")
                    QuickResponse.sendInternalError(
                        "Failure serializing encrypted message",
                        state.conn
                    )
                    return
                }
                val lfs = LocalFS.get()
                val handle = lfs.makeTempFile(gServerDevID, sealed.length.toLong()).getOrElse {
                    logError("commandDevice.makeTempFile failure: $it")
                    QuickResponse.sendInternalError(
                        "Failure creating file for device request",
                        state.conn
                    )
                    return
                }
                handle.getFile().runCatching { writeText(sealed) }.onFailure {
                    logError("commandDevice.writeText failure: $it")
                    QuickResponse.sendInternalError(
                        "Failure saving encrypted device request",
                        state.conn
                    )
                    return
                }
                handle.moveTo(MServerPath("/ out $gServerDevID"))?.let {
                    logError("commandDevice.moveTo failure: $it")
                    QuickResponse.sendInternalError(
                        "Failure moving encrypted device request",
                        state.conn
                    )
                    return
                }

                // call queueMessageForDelivery() with delivery info
                queueMessageForDelivery(gServerAddress, recipient.domain, handle.path)
                ServerResponse(105, "APPROVAL REQUIRED").sendCatching(
                    state.conn,
                    "Failure to send approval required response for ${state.wid}"
                )
                return
            }
            addDevice(db, state.wid!!, devid, devkey, devinfo, DeviceStatus.Registered)?.let {
                logError("commandDevice.addDevice exception: $it")
                QuickResponse.sendInternalError("Error adding device", state.conn)
                return
            }
        }
    }

    // If we've gotten this far, the device is approved and we just need to finish setting up
    // connection state and give the device a success response
    val lfs = LocalFS.get()
    val widPath = MServerPath("/ wsp ${state.wid!!}")
    val widHandle = lfs.entry(widPath)
    val exists = widHandle.exists().getOrElse {
        logError("commandDevice.exists exception for $widPath: $it")
        QuickResponse.sendInternalError(
            "Error checking for workspace root directory",
            state.conn
        )
        return
    }
    if (!exists) {
        lfs.entry(widPath).makeDirectory()?.let {
            logError("commandDevice.makeDirectory exception for $widPath: $it")
            QuickResponse.sendInternalError(
                "Error creating workspace root directory",
                state.conn
            )
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
            logError("commandDevice.getKeyInfo error for ${state.wid}: $it")
            state.loginState = LoginState.NoSession
            state.wid = null
            QuickResponse.sendInternalError(
                "Error finding new device key information",
                state.conn
            )
            return
        }
        if (infopath == null) {
            logError("commandDevice.getKeyInfo missing for ${state.wid}")
            state.loginState = LoginState.NoSession
            state.wid = null
            QuickResponse.sendInternalError(
                "Error finding new device key information",
                state.conn
            )
            return
        }

        val infoHandle = try {
            lfs.entry(infopath)
        } catch (e: Exception) {
            logError("commandDevice.getFile exception for ${state.wid}: $e")
            state.loginState = LoginState.NoSession
            state.wid = null
            QuickResponse.sendInternalError(
                "Error opening device key information",
                state.conn
            )
            return
        }

        val keyInfo = infoHandle.readAll().getOrElse {
            logError("commandDevice.readFile exception for ${state.wid}: $it")
            state.loginState = LoginState.NoSession
            state.wid = null
            QuickResponse.sendInternalError(
                "Error reading device key information",
                state.conn
            )
            return
        }.decodeToString()
        response.code = 203
        response.status = "APPROVED"
        response.data["Key-Info"] = keyInfo
    }

    val isAdmin = state.isAdmin().getOrElse {
        logError("commandDevice.isAdmin exception for ${state.wid}: $it")
        state.loginState = LoginState.NoSession
        state.wid = null
        QuickResponse.sendInternalError(
            "Error checking for admin privileges",
            state.conn
        )
        return
    }
    response.data["Is-Admin"] = if (isAdmin) "True" else "False"
    response.send(state.conn)?.let {
        state.loginState = LoginState.NoSession
        state.wid = null
        QuickResponse.sendInternalError(
            "Error sending successful login information",
            state.conn
        )
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
}

// LOGIN(Login-Type,Workspace-ID, Challenge)
fun commandLogin(state: ClientSession) {

    if (state.loginState != LoginState.NoSession) {
        QuickResponse.sendBadRequest("Session state mismatch", state.conn)
        return
    }

    if (!state.message.hasField("Login-Type")) {
        QuickResponse.sendBadRequest("Missing required field Login-Type", state.conn)
        return
    }
    if (state.message.data["Login-Type"] != "PLAIN") {
        QuickResponse.sendBadRequest("Invalid Login-Type", state.conn)
        return
    }

    val wid = state.getRandomID("Workspace-ID", true) ?: return
    val challenge = state.getCryptoString("Challenge", true) ?: return

    val db = DBConn()
    val status = checkWorkspace(db, wid).getOrElse {
        logError("commandLogin.checkWorkspace exception for ${state.wid}: $it")
        QuickResponse.sendInternalError("Error checking workspace ID", state.conn)
        return
    }
    if (status == null) {
        QuickResponse.sendNotFound("", state.conn)
        return
    }

    when (status) {
        WorkspaceStatus.Active, WorkspaceStatus.Approved -> {
            // This is fine. Everything is fine. 😉
        }

        WorkspaceStatus.Archived -> {
            QuickResponse.sendNotFound("", state.conn)
            return
        }

        WorkspaceStatus.Disabled -> {
            ServerResponse(407, "UNAVAILABLE", "Account disabled")
                .sendCatching(state.conn, "commandLogin.3 error")
            return
        }

        WorkspaceStatus.Pending -> {
            ServerResponse(
                101, "PENDING",
                "Registration awaiting administrator approval"
            )
                .sendCatching(state.conn, "commandLogin.4 error")
            return
        }

        WorkspaceStatus.Preregistered -> {
            ServerResponse(
                416, "PROCESS INCOMPLETE",
                "Workspace requires use of registration code"
            )
                .sendCatching(state.conn, "commandLogin.5 error")
            return
        }

        WorkspaceStatus.Suspended -> {
            ServerResponse(407, "UNAVAILABLE", "Account suspended")
                .sendCatching(state.conn, "commandLogin.6 error")
            return
        }

        WorkspaceStatus.Unpaid -> {
            ServerResponse(406, "PAYMENT REQUIRED")
                .sendCatching(state.conn, "commandLogin.7 error")
            return
        }
    }

    // We got this far, so decrypt the challenge and send it to the client
    val orgPair = getEncryptionPair(db).getOrElse {
        logError("commandLogin.getEncryptionPair exception: $it")
        QuickResponse.sendInternalError(
            "Server can't process client login challenge",
            state.conn
        )
        return
    }

    val decrypted = orgPair.decrypt(challenge).getOrElse {
        ServerResponse(306, "KEY FAILURE", "Client challenge decryption failure")
            .sendCatching(state.conn, "commandLogin key failure message send error")
        return
    }.decodeToString()

    val passInfo = getPasswordInfo(db, wid).getOrElse {
        logError("commandLogin.getPasswordInfo exception: $it")
        QuickResponse.sendInternalError(
            "Server error getting password information",
            state.conn
        )
        return
    }
    if (passInfo == null) {
        QuickResponse.sendNotFound("Password information not found", state.conn)
        return
    }

    state.wid = wid
    state.loginState = LoginState.AwaitingPassword
    ServerResponse(
        100, "CONTINUE", "", mutableMapOf(
            "Response" to decrypted,
            "Password-Algorithm" to passInfo.algorithm,
            "Password-Salt" to passInfo.salt,
            "Password-Parameters" to passInfo.parameters,
        )
    ).sendCatching(state.conn, "commandLogin success message send error")
}

// LOGOUT()
fun commandLogout(state: ClientSession) {
    state.loginState = LoginState.NoSession
    state.wid = null

    ServerResponse(200, "OK").sendCatching(
        state.conn,
        "commandLogout success message send error"
    )
}

// PASSWORD(Password-Hash)
fun commandPassword(state: ClientSession) {
    if (!state.message.hasField("Password-Hash")) {
        QuickResponse.sendBadRequest("Missing required field Password-Hash", state.conn)
        return
    }
    if (state.loginState != LoginState.AwaitingPassword) {
        QuickResponse.sendBadRequest("Session state mismatch", state.conn)
        return
    }

    val db = DBConn()
    val match = checkPassword(db, state.wid!!, state.message.data["Password-Hash"]!!).getOrElse {
        logError("commandPassword.checkPassword error: $it")
        QuickResponse.sendInternalError("Internal error checking password", state.conn)
        return
    }

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
    ServerResponse(100, "CONTINUE").sendCatching(
        state.conn,
        "commandPassword continue message failure"
    )
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
    )
        .send(state.conn)?.let { return it.toFailure() }

    val req = ClientRequest.receive(state.conn.getInputStream())
        .getOrElse { return it.toFailure() }
    if (req.action == "CANCEL") return Result.failure(CancelException())

    if (req.action != "DEVICE") {
        QuickResponse.sendBadRequest("Session state mismatch", state.conn)
        return Result.success(false)
    }

    val missingField = req.validate(setOf("Device-ID", "Device-Key", "Response"))
    if (missingField != null) {
        QuickResponse.sendBadRequest("Missing required field $missingField", state.conn)
        return Result.success(false)
    }
    if (devkey.toString() != req.data["Device-Key"]) {
        QuickResponse.sendBadRequest("Device key mismatch", state.conn)
        return Result.success(false)
    }

    return Result.success(challenge == req.data["Response"])
}