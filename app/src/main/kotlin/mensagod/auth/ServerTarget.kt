package mensagod.auth

import libkeycard.MAddress
import libkeycard.UserID
import mensagod.DBConn
import mensagod.DatabaseCorruptionException
import mensagod.dbcmds.resolveAddress
import mensagod.gServerDomain

/**
 * The ServerTarget class is used for actions which operate at the server level of scope. This
 * includes workspace registration and preregistration.
 */
class ServerTarget: AuthTarget {

    override fun isAuthorized(actor: AuthActor, action: AuthAction): Boolean {
        when (action) {
            AuthAction.Preregister -> {
                // At this point only users may preregister a workspace
                if (actor.getType() != AuthActorType.WID) return false
                actor as WIDActor

                // For the moment, only the administrator can preregister workspaces
                val addr = MAddress.fromParts(UserID.fromString("admin")!!, gServerDomain)
                val adminWID = resolveAddress(DBConn().connect(), addr)
                    ?: throw DatabaseCorruptionException("Administrator WID missing from database")

                return actor.wid == adminWID
            }
            else -> return false
        }
    }
}