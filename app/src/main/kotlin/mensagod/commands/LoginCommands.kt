package mensagod.commands

import mensagod.*
import mensagod.dbcmds.WorkspaceStatus
import mensagod.dbcmds.checkWorkspace
import mensagod.dbcmds.getEncryptionPair
import mensagod.dbcmds.getPasswordInfo

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
    val orgPair = try { getEncryptionPair() }
    catch (e: Exception) {
        logError("commandLogin.getEncryptionPair exception: $e")
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

    try {
        ServerResponse(100, "CONTINUE", "", mutableMapOf(
            "Response" to decrypted.toString(),
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
    TODO("Implement commandPassword($state)")
}
