package mensagod.commands

import keznacl.Argon2idPassword
import keznacl.getSupportedAsymmetricAlgorithms
import libkeycard.MAddress
import libkeycard.RandomID
import libkeycard.UserID
import libkeycard.WAddress
import libmensago.MServerPath
import mensagod.*
import mensagod.auth.AuthAction
import mensagod.auth.ServerTarget
import mensagod.auth.WIDActor
import mensagod.dbcmds.*

// PREREG(User-ID="", Workspace-ID="",Domain="")
fun commandPreregister(state: ClientSession) {

    if (!state.requireLogin()) return
    if (!ServerTarget().isAuthorized(WIDActor(state.wid!!), AuthAction.Preregister)) {
        ServerResponse.sendForbidden("Only admins can preregister accounts", state.conn)
        return
    }

    val uid = state.getUserID("User-ID", false)
    val wid = state.getRandomID("Workspace-ID", false)
    val domain = state.getDomain("Domain", false)

    val db = DBConn()
    val outUID = if (uid != null) {
        try { resolveUserID(db, uid) }
        catch (e: Exception) {
            logError("commandPreregister.resolveUserID exception: $e")
            ServerResponse.sendInternalError("uid lookup error", state.conn)
            return
        }?.let{
            try { ServerResponse(408, "RESOURCE EXISTS", "user ID exists")
                .send(state.conn) }
            catch (e: Exception) {
                logDebug("commandPreregister.resolveUserID exists send error: $e")
            }
            return
        }
        uid
    } else null

    val outWID = if (wid != null) {
        try { checkWorkspace(db, wid) }
        catch (e: Exception) {
            logError("commandPreregister.checkWorkspace exception: $e")
            ServerResponse.sendInternalError("wid lookup error", state.conn)
            return
        }?.let{
            try { ServerResponse(408, "RESOURCE EXISTS", "workspace ID exists")
                .send(state.conn) }
            catch (e: Exception) {
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
                if (checkWorkspace(db, tempWID) == null)
                    tempWID
                else
                    null
            }
            catch (e: Exception) {
                logError("commandPreregister.checkWorkspace exception: $e")
                ServerResponse.sendInternalError("wid lookup error", state.conn)
                return
            }
        } while (newWID == null)
        newWID
    }

    val outDom = domain ?: gServerDomain

    // Now that we've gone through the pain of covering for missing arguments and validating the
    // ones that actually exist, preregister the account.
    val regcode = gRegCodeGenerator.getPassphrase(
        ServerConfig.get().getInteger("security.diceware_wordcount")!!)
    val reghash = Argon2idPassword().updateHash(regcode).getOrElse {
        logError("commandPreregister.hashRegCode exception: $it")
        ServerResponse.sendInternalError("registration code hashing error", state.conn)
        return
    }

    try { preregWorkspace(db, outWID, outUID, outDom, reghash) }
    catch (e: ResourceExistsException) {
        ServerResponse(408, "RESOURCE EXISTS")
        return
    }
    catch (e: Exception) {
        logError("commandPreregister.preregWorkspace exception: $e")
        ServerResponse.sendInternalError("preregistration error", state.conn)
    }

    val lfs = LocalFS.get()
    val handle = lfs.entry(MServerPath("/ wsp $outWID"))
    handle.makeDirectory()?.let {
        logError("commandPreregister.makeWorkspace exception: $it")
        ServerResponse.sendInternalError("preregistration workspace creation failure",
            state.conn)
        return
    }

    val resp = ServerResponse(200, "OK", "", mutableMapOf(
        "Workspace-ID" to outWID.toString(),
        "Domain" to outDom.toString(),
        "Reg-Code" to regcode,
    ))
    if (outUID != null) resp.data["User-ID"] = outUID.toString()
    try { resp.send(state.conn) }
    catch (e: Exception) { logDebug("commandRegCode success message send error: $e") }
}

// REGCODE(User-ID, Reg-Code, Password-Hash, Password-Algorithm, Device-ID, Device-Key,
//     Device-Info, Password-Salt="", Password-Parameters="", Domain="")
// REGCODE(Workspace-ID, Reg-Code, Password-Hash, Password-Algorithm, Device-ID, Device-Key,
//     Device-Info, Password-Salt="", Password-Parameters="", Domain="")
fun commandRegCode(state: ClientSession) {

    state.message.validate(setOf("Reg-Code", "Password-Hash", "Password-Algorithm"))?.let {
        ServerResponse.sendBadRequest("Missing required field $it", state.conn)
        return
    }

    val devid = state.getRandomID("Device-ID", true) ?: return
    val devkey = state.getCryptoString("Device-Key", true) ?: return
    val devinfo = state.getCryptoString("Device-Info", true) ?: return
    val domain = state.getDomain("Domain", false, gServerDomain)!!

    val regCodeLen = state.message.data["Reg-Code"]!!.codePoints().count()
    if (regCodeLen > 128 || regCodeLen < 16) {
        ServerResponse.sendBadRequest("Invalid registration code", state.conn)
        return
    }

    // The password field must pass some basic checks for length, but because we will be hashing
    // the thing with Argon2id, even if the client does a dumb thing and submit a cleartext
    // password, there will be a pretty decent baseline of security in place.
    val passLen = state.message.data["Password-Hash"]!!.codePoints().count()
    if (passLen > 128 || passLen < 16) {
        ServerResponse.sendBadRequest("Invalid password hash", state.conn)
        return
    }

    var uid = state.getUserID("User-ID", false)
    if (uid == null) {
        val wid = state.getRandomID("Workspace-ID", true) ?: return
        uid = UserID.fromWID(wid)
    }

    if (!getSupportedAsymmetricAlgorithms().contains(devkey.prefix)) {
        ServerResponse(309, "ENCRYPTION TYPE NOT SUPPORTED",
            "Supported: "+ getSupportedAsymmetricAlgorithms().joinToString(","))
                .send(state.conn)
        return
    }

    val db = DBConn()
    val regInfo = try {
        checkRegCode(db, MAddress.fromParts(uid,domain), state.message.data["Reg-Code"]!!)
    } catch (e: Exception) {
        logError("Internal error commandRegCode.checkRegCode: $e")
        ServerResponse.sendInternalError("commandRegCode.1", state.conn)
        return
    }

    if (regInfo == null) {
        ServerResponse(401, "UNAUTHORIZED").send(state.conn)
        return
    }

    try {
        addWorkspace(db, regInfo.first, regInfo.second, domain,
            state.message.data["Password-Hash"]!!, state.message.data["Password-Algorithm"]!!,
                state.message.data["Salt"] ?: "",
                state.message.data["Password-Parameters"] ?: "", WorkspaceStatus.Active,
                WorkspaceType.Individual)
    }
    catch (e: ResourceExistsException) {
        ServerResponse(408, "RESOURCE EXISTS", "workspace is already registered")
        return
    }
    catch (e: Exception) {
        logError("Internal error commandRegCode.addWorkspace: $e")
        ServerResponse.sendInternalError("commandRegCode.2", state.conn)
        return
    }

    addDevice(db, regInfo.first, devid, devkey, devinfo, DeviceStatus.Registered)?.let {
        logError("commandRegCode.addDevice: $it")
        ServerResponse.sendInternalError("commandRegCode.3", state.conn)
        return
    }

    try { deletePrereg(db, WAddress.fromParts(regInfo.first, domain)) }
    catch (e: Exception) {
        logError("commandRegCode.deletePrereg: $e")
        ServerResponse.sendInternalError("commandRegCode.4", state.conn)
        return
    }

    try {
        ServerResponse(201, "REGISTERED", "", mutableMapOf(
            "Workspace-ID" to regInfo.first.toString(),
            "User-ID" to uid.toString(),
            "Domain" to domain.toString(),
        )).send(state.conn)
    } catch (e: Exception) { logDebug("commandRegCode success message send error: $e") }
}
