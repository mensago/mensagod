package mensagod.auth

import libkeycard.MAddress
import libkeycard.RandomID
import libkeycard.UserID
import mensagod.DatabaseCorruptionException
import mensagod.dbcmds.resolveAddress
import mensagod.gServerDomain

/**
 * The WorkspaceTarget class represents a workspace identified by its workspace ID. It is used for
 * situations where an actor wants to perform an action on the workspace itself, such as changing
 * its status.
 */
class WorkspaceTarget(val wid: RandomID): AuthTarget {

    override fun isAuthorized(actor: AuthActor, action: AuthAction): Boolean {
        when (action) {
            AuthAction.Preregister -> {
                // At this point only users may preregister a workspace
                if (actor.getType() != AuthActorType.WID) return false


                val addr = MAddress.fromParts(UserID.fromString("admin")!!, gServerDomain)
                val adminWID = resolveAddress(addr)
                    ?: throw DatabaseCorruptionException("Administrator WID missing from database")
                return wid == adminWID
            }
            else -> return false
        }
    }
}
