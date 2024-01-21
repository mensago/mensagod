package mensagod.commands

import keznacl.Argon2idPassword
import libkeycard.RandomID
import mensagod.*
import mensagod.dbcmds.checkWorkspace
import mensagod.dbcmds.preregWorkspace
import mensagod.dbcmds.resolveUserID
import mensagod.fs.LocalFS

// PREREG(User-ID="", Workspace-ID="",Domain="")
fun commandPreregister(state: ClientSession) {

    if (!state.requireAdminLogin()) return

    val uid = state.getUserID("User-ID", false)
    val wid = state.getRandomID("Workspace-ID", false)
    val domain = state.getDomain("Domain", false)

    val outUID = if (uid != null) {
        try { resolveUserID(uid) }
        catch (e: Exception) {
            logError("commandPreregister.resolveUserID exception: $e")
            ServerResponse.sendInternalError("uid lookup error", state.conn)
            return
        }?.let{
            try { ServerResponse(408, "RESOURCE EXISTS", "user ID exists")
                .send(state.conn) }
            catch (e: Exception) {
                logError("commandPreregister.resolveUserID exists send error: $e")
            }
            return
        }
        uid
    } else null

    val outWID = if (wid != null) {
        try { checkWorkspace(wid) }
        catch (e: Exception) {
            logError("commandPreregister.checkWorkspace exception: $e")
            ServerResponse.sendInternalError("wid lookup error", state.conn)
            return
        }?.let{
            try { ServerResponse(408, "RESOURCE EXISTS", "workspace ID exists")
                .send(state.conn) }
            catch (e: Exception) {
                logError("commandPreregister.checkWorkspace exists send error: $e")
            }
            return
        }
        wid
    } else {
        var newWID: RandomID? = null
        do {
            newWID = try {
                val tempWID = RandomID.generate()
                if (checkWorkspace(tempWID) == null)
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
        ServerConfig.get().getInteger("security.diceware_wordcount"))
    val reghash = Argon2idPassword().updateHash("regcode").getOrElse {
        logError("commandPreregister.hashRegCode exception: $it")
        ServerResponse.sendInternalError("registration code hashing error", state.conn)
        return
    }

    try { preregWorkspace(outWID, outUID, outDom, reghash) }
    catch (e: Exception) {
        logError("commandPreregister.preregWorkspace exception: $e")
        ServerResponse.sendInternalError("preregistration error", state.conn)
    }

    val lfs = LocalFS.get()
    try { lfs.makeDirectory(MServerPath("/ wsp $wid")) }
    catch (e: Exception) {
        logError("commandPreregister.makeWorkspace exception: $e")
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
    resp.send(state.conn)
}
