package mensagod.commands

import keznacl.Base85
import keznacl.CryptoString
import keznacl.EncryptionKey
import keznacl.UnsupportedAlgorithmException
import libmensago.DeviceApprovalMsg
import libmensago.MServerPath
import mensagod.*
import mensagod.dbcmds.*
import java.security.GeneralSecurityException
import java.security.SecureRandom


// DEVICE(Deice-ID, Device-Key, Client-Info)
fun commandDevice(state: ClientSession) {
    if (state.loginState != LoginState.AwaitingDeviceID) {
        ServerResponse.sendBadRequest("Session mismatch error", state.conn)
        return
    }

    val devid = state.getRandomID("Device-ID", true) ?: return
    val devkey = state.getCryptoString("Device-Key", true) ?: return
    val devinfo = state.getCryptoString("Device-Info", false)

    val db = DBConn()
    val devstatus = getDeviceStatus(db, state.wid!!, devid).getOrElse {
        logError("commandDevice.getDeviceStatus exception: $it")
        ServerResponse.sendInternalError("Server can't get device status", state.conn)
        return
    }

    when (devstatus) {
        DeviceStatus.Blocked -> {
            if (!ServerResponse(403, "FORBIDDEN")
                    .sendCatching(state.conn, "commandDevice.1"))
                return
        }
        DeviceStatus.Pending -> {
            if (!ServerResponse(101, "PENDING", "Awaiting device approval")
                    .sendCatching(state.conn, "commandDevice.2"))
                return
        }
        DeviceStatus.Registered, DeviceStatus.Approved -> {
            // The device is part of the workspace, so now we issue undergo a challenge-response
            // to ensure that the device really is authorized and the key wasn't stolen by an
            // impostor
            val success = try { challengeDevice(state, devkey) }
            catch (e: Exception) {
                logError("commandDevice.challengeDevice exception: $e")
                ServerResponse.sendInternalError("Error authenticating client device",
                    state.conn)
                return
            }

            if (devinfo != null) {
                updateDeviceInfo(db, state.wid!!, devid, devinfo)?.let {
                    logError("commandDevice.challengeDevice exception: $it")
                    ServerResponse.sendInternalError("Error updating device info",
                        state.conn)
                    return
                }
            }

            if (!success) return
        }
        DeviceStatus.NotRegistered -> {
            if (devinfo == null) {
                ServerResponse.sendBadRequest("Device-Info field required for new devices",
                    state.conn)
                return
            }

            // 1) Check to see if the workspace has any devices registered.
            val devCount = countDevices(db, state.wid!!).getOrElse {
                logError("commandDevice.countDevices exception: $it")
                ServerResponse.sendInternalError("Error checking device count",
                    state.conn)
                return
            }

            // 2) If there are multiple devices, push out an approval request and return
            if (devCount > 0) {
                // Feature: LocalDelivery
                // Feature: DeviceManagement

                val recipient = try {
                    val out = resolveWID(db, state.wid!!)
                    if (out == null) {
                        logError("commandDevice.resolveWID returned null for wid ${state.wid!!}")
                        ServerResponse.sendInternalError("Server error: workspace missing",
                            state.conn)
                        return
                    }
                    out
                }
                catch (e: Exception) {
                    logError("commandDevice.resolveWID exception: $e")
                    ServerResponse.sendInternalError("Error looking up workspace address",
                        state.conn)
                    return
                }

                val msg = DeviceApprovalMsg.new(gServerAddress, recipient, state.conn.inetAddress)
                    .getOrElse {
                        logError("commandDevice.createApprovalMsg exception: $it")
                        ServerResponse.sendInternalError(
                            "Error creating device approval request", state.conn)
                        return
                    }
                // Create auth message and save to file
                // call queueMessageForDelivery() with delivery info

                // TODO: Implement device handling
                println("New device handling state encountered")
            }
            addDevice(db, state.wid!!, devid, devkey, devinfo, DeviceStatus.Registered)?.let {
                logError("commandDevice.addDevice exception: $it")
                ServerResponse.sendInternalError("Error adding device", state.conn)
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
        ServerResponse.sendInternalError("Error checking for workspace root directory",
            state.conn)
        return
    }
    if (!exists) {
        lfs.entry(widPath).makeDirectory()?.let {
            logError("commandDevice.makeDirectory exception for $widPath: $it")
            ServerResponse.sendInternalError("Error creating workspace root directory",
                state.conn)
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
            ServerResponse.sendInternalError("Error finding new device key information",
                state.conn)
            return
        }
        if (infopath == null) {
            logError("commandDevice.getKeyInfo missing for ${state.wid}")
            state.loginState = LoginState.NoSession
            state.wid = null
            ServerResponse.sendInternalError("Error finding new device key information",
                state.conn)
            return
        }

        val infoHandle = try { lfs.entry(infopath) }
        catch (e: Exception) {
            logError("commandDevice.getFile exception for ${state.wid}: $e")
            state.loginState = LoginState.NoSession
            state.wid = null
            ServerResponse.sendInternalError("Error opening device key information",
                state.conn)
            return
        }

        val keyInfo = infoHandle.readAll().getOrElse {
            logError("commandDevice.readFile exception for ${state.wid}: $it")
            state.loginState = LoginState.NoSession
            state.wid = null
            ServerResponse.sendInternalError("Error reading device key information",
                state.conn)
            return
        }.decodeToString()
        response.code = 203
        response.status = "APPROVED"
        response.data["Key-Info"] = keyInfo
    }

    response.data["Is-Admin"] = if (state.isAdmin()) "True" else "False"
    try { response.send(state.conn) }
    catch (e: Exception) {
        state.loginState = LoginState.NoSession
        state.wid = null
        ServerResponse.sendInternalError("Error sending successful login information",
            state.conn)
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
        ServerResponse.sendBadRequest("Session state mismatch", state.conn)
        return
    }

    if (!state.message.hasField("Login-Type")) {
        ServerResponse.sendBadRequest("Missing required field Login-Type", state.conn)
        return
    }
    if (state.message.data["Login-Type"] != "PLAIN") {
        ServerResponse.sendBadRequest("Invalid Login-Type", state.conn)
        return
    }

    val wid = state.getRandomID("Workspace-ID", true) ?: return
    val challenge = state.getCryptoString("Challenge", true) ?: return

    val db = DBConn()
    val status = checkWorkspace(db, wid)
    if (status == null) {
        try { ServerResponse(404, "NOT FOUND").send(state.conn) }
        catch (e: Exception) { logDebug("commandLogin.1 error: $e") }
        return
    }

    when (status) {
        WorkspaceStatus.Active, WorkspaceStatus.Approved -> {
            // This is fine. Everything is fine. 😉
        }
        WorkspaceStatus.Archived -> {
            try { ServerResponse(404, "NOT FOUND").send(state.conn) }
            catch (e: Exception) { logDebug("commandLogin.2 error: $e") }
            return
        }
        WorkspaceStatus.Disabled -> {
            try {
                ServerResponse(407, "UNAVAILABLE", "Account disabled")
                .send(state.conn)
            }
            catch (e: Exception) { logDebug("commandLogin.3 error: $e") }
            return
        }
        WorkspaceStatus.Pending -> {
            try {
                ServerResponse(101, "PENDING",
                    "Registration awaiting administrator approval").send(state.conn)
            } catch (e: Exception) { logDebug("commandLogin.4 error: $e") }
            return
        }
        WorkspaceStatus.Preregistered -> {
            try {
                ServerResponse(416, "PROCESS INCOMPLETE",
                    "Workspace requires usage of registration code").send(state.conn)
            } catch (e: Exception) { logDebug("commandLogin.5 error: $e") }
            return
        }
        WorkspaceStatus.Suspended -> {
            try {
                ServerResponse(407, "UNAVAILABLE", "Account suspended")
                    .send(state.conn)
            }
            catch (e: Exception) { logDebug("commandLogin.6 error: $e") }
            return
        }
        WorkspaceStatus.Unpaid -> {
            try { ServerResponse(406, "PAYMENT REQUIRED").send(state.conn) }
            catch (e: Exception) { logDebug("commandLogin.7 error: $e") }
            return
        }
    }

    // We got this far, so decrypt the challenge and send it to the client
    val orgPair = getEncryptionPair(db).getOrElse {
        logError("commandLogin.getEncryptionPair exception: $it")
        ServerResponse.sendInternalError("Server can't process client login challenge",
            state.conn)
        return
    }

    val decrypted = orgPair.decrypt(challenge).getOrElse {
        ServerResponse(306, "KEY FAILURE", "Client challenge decryption failure")
            .send(state.conn)
        return
    }.decodeToString()

    val passInfo = getPasswordInfo(db, wid)
    if (passInfo == null) {
        try { ServerResponse(404, "NOT FOUND", "Password information not found")
            .send(state.conn) }
        catch (e: Exception) { logDebug("commandLogin.8 error: $e") }
        return
    }

    state.wid = wid
    try {
        ServerResponse(100, "CONTINUE", "", mutableMapOf(
            "Response" to decrypted,
            "Password-Algorithm" to passInfo.algorithm,
            "Password-Salt" to passInfo.salt,
            "Password-Parameters" to passInfo.parameters,
        )).send(state.conn)
    } catch (e: Exception) { logDebug("commandLogin success message send error: $e") }
}

// LOGOUT()
fun commandLogout(state: ClientSession) {
    state.loginState = LoginState.NoSession
    state.wid = null

    try {
        ServerResponse(200, "OK").send(state.conn)
    } catch (e: Exception) { logDebug("commandLogout success message send error: $e") }
}

// PASSWORD(Password-Hash)
fun commandPassword(state: ClientSession) {
    if (!state.message.hasField("Password-Hash")) {
        ServerResponse.sendBadRequest("Missing required field Password-Hash", state.conn)
        return
    }
    if (state.loginState != LoginState.AwaitingPassword) {
        ServerResponse.sendBadRequest("Session state mismatch", state.conn)
        return
    }

    val db = DBConn()
    val match = try { checkPassword(db, state.wid!!, state.message.data["Password-Hash"]!!) }
    catch (e: Exception) {
        logError("commandPassword.checkPassword error: $e")
        ServerResponse.sendInternalError("Internal error checking password", state.conn)
        return
    }

    if (!match) {
        val delay = ServerConfig.get().getInteger("security.failure_delay_sec")!!
        Thread.sleep(delay * 1000L)
        try {
            ServerResponse(402, "AUTHENTICATION FAILURE").send(state.conn)
        } catch (e: Exception) { logDebug("commandPassword auth fail message send error: $e") }
        return
    }

    state.loginState = LoginState.AwaitingDeviceID
    ServerResponse(100, "CONTINUE").send(state.conn)
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
fun challengeDevice(state: ClientSession, devkey: CryptoString): Boolean {
    // 1) Generate a 32-byte random string of bytes
    // 2) Encode string in base85
    // 3) Encrypt said string, encode in base85, and return it as part of 100 CONTINUE response
    // 4) Wait for response from client and compare response to original base85 string
    // 5) If strings don't match, respond to client with 402 Authentication Failure and return false
    // 6) If strings match respond to client with 200 OK and return true/nil

    val realKey = EncryptionKey.from(devkey).getOrThrow()

    val rng = SecureRandom()
    val rawBytes = ByteArray(32)
    rng.nextBytes(rawBytes)
    val challenge = Base85.rfc1924Encoder.encode(rawBytes)
    val encrypted = realKey.encrypt(challenge.toByteArray()).getOrThrow()
    ServerResponse(100, "CONTINUE", "",
        mutableMapOf("Challenge" to encrypted.toString())).send(state.conn)
    // We purposely don't try to catch the send error, as that's part of the caller's responsibility

    val req = ClientRequest.receive(state.conn.getInputStream())
    if (req.action == "CANCEL") throw CancelException()

    if (req.action != "DEVICE") {
        ServerResponse.sendBadRequest("Session state mismatch", state.conn)
        return false
    }

    val missingField = req.validate(setOf("Device-ID", "Device-Key", "Response"))
    if (missingField != null)  {
        ServerResponse.sendBadRequest("Missing required field $missingField", state.conn)
        return false
    }
    if (devkey.toString() != req.data["Device-Key"]) {
        ServerResponse.sendBadRequest("Device key mismatch", state.conn)
        return false
    }

    return challenge == req.data["Response"]
}