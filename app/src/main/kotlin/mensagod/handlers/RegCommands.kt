package mensagod.handlers

import keznacl.Argon2idPassword
import keznacl.getSupportedAsymmetricAlgorithms
import libkeycard.MAddress
import libkeycard.RandomID
import libkeycard.UserID
import libkeycard.WAddress
import libmensago.MServerPath
import libmensago.ResourceExistsException
import libmensago.ServerResponse
import mensagod.*
import mensagod.auth.AuthAction
import mensagod.auth.ServerTarget
import mensagod.auth.WIDActor
import mensagod.dbcmds.*

// PREREG(User-ID="", Workspace-ID="",Domain="")
fun commandPreregister(state: ClientSession) {

    if (!state.requireLogin()) return
    val isAuthorized = ServerTarget().isAuthorized(WIDActor(state.wid!!), AuthAction.Preregister)
        .getOrElse {
            logError("commandPreregister.checkAuth exception: $it")
            QuickResponse.sendInternalError("authorization check error", state.conn)
            return
        }
    if (!isAuthorized) {
        QuickResponse.sendForbidden("Only admins can preregister accounts", state.conn)
        return
    }

    val uid = state.getUserID("User-ID", false)
    val wid = state.getRandomID("Workspace-ID", false)
    val domain = state.getDomain("Domain", false)

    val db = DBConn()
    val outUID = if (uid != null) {
        resolveUserID(db, uid).getOrElse {
            logError("commandPreregister.resolveUserID exception: $it")
            QuickResponse.sendInternalError("uid lookup error", state.conn)
            return
        }?.let {
            ServerResponse(408, "RESOURCE EXISTS", "user ID exists")
                .sendCatching(
                    state.conn,
                    "commandPreregister.resolveUserID exists send error"
                )
            return
        }
        uid
    } else null

    val outWID = if (wid != null) {
        checkWorkspace(db, wid).getOrElse {
            logError("commandPreregister.checkWorkspace exception: $it")
            QuickResponse.sendInternalError("wid lookup error", state.conn)
            return
        }?.let {
            try {
                ServerResponse(408, "RESOURCE EXISTS", "workspace ID exists")
                    .send(state.conn)
            } catch (e: Exception) {
                logDebug("commandPreregister.checkWorkspace exists send error: $e")
            }
            return
        }
        wid
    } else {
        var newWID: RandomID?
        do {
            newWID = try {
                val tempWID = RandomID.generate()
                val status = checkWorkspace(db, tempWID).getOrElse {
                    logError("commandPreregister.checkWorkspace(newWID) exception: $it")
                    QuickResponse.sendInternalError("new wid lookup error", state.conn)
                    return
                }
                if (status == null)
                    tempWID
                else
                    null
            } catch (e: Exception) {
                logError("commandPreregister.checkWorkspace exception: $e")
                QuickResponse.sendInternalError("wid lookup error", state.conn)
                return
            }
        } while (newWID == null)
        newWID
    }

    val outDom = domain ?: gServerDomain

    // Now that we've gone through the pain of covering for missing arguments and validating the
    // ones that actually exist, preregister the account.
    val regcode = gRegCodeGenerator.getPassphrase(
        ServerConfig.get().getInteger("security.diceware_wordcount")!!
    )
    val reghash = Argon2idPassword().updateHash(regcode).getOrElse {
        logError("commandPreregister.hashRegCode exception: $it")
        QuickResponse.sendInternalError("registration code hashing error", state.conn)
        return
    }

    preregWorkspace(db, outWID, outUID, outDom, reghash)?.let {
        if (it is ResourceExistsException) {
            ServerResponse(408, "RESOURCE EXISTS")
                .sendCatching(state.conn, "commandPreregister error sending resource exists")
            return
        }
        logError("commandPreregister.preregWorkspace exception: $it")
        QuickResponse.sendInternalError("preregistration error", state.conn)
    }

    val lfs = LocalFS.get()
    val handle = lfs.entry(MServerPath("/ wsp $outWID"))
    handle.makeDirectory()?.let {
        logError("commandPreregister.makeWorkspace exception: $it")
        QuickResponse.sendInternalError(
            "preregistration workspace creation failure",
            state.conn
        )
        return
    }

    val resp = ServerResponse(
        200, "OK", "", mutableMapOf(
            "Workspace-ID" to outWID.toString(),
            "Domain" to outDom.toString(),
            "Reg-Code" to regcode,
        )
    )
    if (outUID != null) resp.data["User-ID"] = outUID.toString()
    resp.sendCatching(state.conn, "commandRegCode success message send error")
}

// REGCODE(User-ID, Reg-Code, Password-Hash, Password-Algorithm, Device-ID, Device-Key,
//     Device-Info, Password-Salt="", Password-Parameters="", Domain="")
// REGCODE(Workspace-ID, Reg-Code, Password-Hash, Password-Algorithm, Device-ID, Device-Key,
//     Device-Info, Password-Salt="", Password-Parameters="", Domain="")
fun commandRegCode(state: ClientSession) {

    state.message.validate(setOf("Reg-Code", "Password-Hash", "Password-Algorithm"))?.let {
        QuickResponse.sendBadRequest("Missing required field $it", state.conn)
        return
    }

    val devid = state.getRandomID("Device-ID", true) ?: return
    val devkey = state.getCryptoString("Device-Key", true) ?: return
    val devinfo = state.getCryptoString("Device-Info", true) ?: return
    val domain = state.getDomain("Domain", false, gServerDomain)!!

    val regCodeLen = state.message.data["Reg-Code"]!!.codePoints().count()
    if (regCodeLen > 128 || regCodeLen < 16) {
        QuickResponse.sendBadRequest("Invalid registration code", state.conn)
        return
    }

    // The password field must pass some basic checks for length, but because we will be hashing
    // the thing with Argon2id, even if the client does a dumb thing and submit a cleartext
    // password, there will be a pretty decent baseline of security in place.
    val passLen = state.message.data["Password-Hash"]!!.codePoints().count()
    if (passLen > 128 || passLen < 16) {
        QuickResponse.sendBadRequest("Invalid password hash", state.conn)
        return
    }

    var uid = state.getUserID("User-ID", false)
    if (uid == null) {
        val wid = state.getRandomID("Workspace-ID", true) ?: return
        uid = UserID.fromWID(wid)
    }

    if (!getSupportedAsymmetricAlgorithms().contains(devkey.prefix)) {
        ServerResponse(
            309, "ENCRYPTION TYPE NOT SUPPORTED",
            "Supported: " + getSupportedAsymmetricAlgorithms().joinToString(",")
        )
            .sendCatching(
                state.conn,
                "commandRegCode: failed to send bad encryption message"
            )
        return
    }

    val db = DBConn()
    val regInfo =
        checkRegCode(db, MAddress.fromParts(uid, domain), state.message.data["Reg-Code"]!!)
            .getOrElse {
                logError("Internal error commandRegCode.checkRegCode: $it")
                QuickResponse.sendInternalError("commandRegCode.1", state.conn)
                return
            }

    if (regInfo == null) {
        ServerResponse(401, "UNAUTHORIZED").sendCatching(
            state.conn,
            "commandRegCode: Failed to send unauthorized message"
        )
        return
    }

    // Although we have been given a password hash, we still need to hash it on this side, as well,
    // so that if the client foolishly presented us with a cleartext password, the client's
    // password isn't stored in cleartext in the database.
    val serverHash = Argon2idPassword().updateHash(state.message.data["Password-Hash"]!!)
        .getOrElse {
            logError("Internal error commandRegCode.hashPassword: $it")
            QuickResponse.sendInternalError("Server error hashing password", state.conn)
            return
        }
    addWorkspace(
        db, regInfo.first, regInfo.second, domain, serverHash,
        state.message.data["Password-Algorithm"]!!, state.message.data["Password-Salt"] ?: "",
        state.message.data["Password-Parameters"] ?: "", WorkspaceStatus.Active,
        WorkspaceType.Individual
    )?.let {
        if (it is ResourceExistsException) {
            ServerResponse(
                408, "RESOURCE EXISTS",
                "workspace is already registered"
            ).sendCatching(
                state.conn,
                "Failed to send workspace-exists message"
            )
            return
        }
        logError("Internal error commandRegCode.addWorkspace: $it")
        QuickResponse.sendInternalError("commandRegCode.2", state.conn)
        return
    }

    addDevice(db, regInfo.first, devid, devkey, devinfo, DeviceStatus.Registered)?.let {
        logError("commandRegCode.addDevice: $it")
        QuickResponse.sendInternalError("commandRegCode.3", state.conn)
        return
    }

    deletePrereg(db, WAddress.fromParts(regInfo.first, domain))?.let {
        logError("commandRegCode.deletePrereg: $it")
        QuickResponse.sendInternalError("commandRegCode.4", state.conn)
        return
    }

    ServerResponse(
        201, "REGISTERED", "", mutableMapOf(
            "Workspace-ID" to regInfo.first.toString(),
            "User-ID" to uid.toString(),
            "Domain" to domain.toString(),
        )
    ).send(state.conn)?.let {
        logDebug("commandRegCode success message send error: $it")
    }
}
