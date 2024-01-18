package mensagod.commands

import libkeycard.RandomID
import mensagod.ClientSession
import mensagod.dbcmds.checkWorkspace
import mensagod.dbcmds.resolveUserID
import mensagod.gServerDomain
import mensagod.logError

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
        wid
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

    // TODO: Finish commandPreregister
}
