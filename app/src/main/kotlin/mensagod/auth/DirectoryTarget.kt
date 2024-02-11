package mensagod.auth

import libkeycard.MAddress
import libkeycard.RandomID
import mensagod.DBConn
import mensagod.MServerPath
import mensagod.dbcmds.resolveAddress
import mensagod.gServerDomain
import mensagod.logError

/**
 * The DirectoryTarget class is used for actions which operate on a directory.
 */
class DirectoryTarget private constructor(val path: MServerPath): AuthTarget {

    override fun isAuthorized(actor: AuthActor, action: AuthAction): Boolean {
        when (action) {
            AuthAction.Create, AuthAction.Delete -> {
                if (actor.getType() != AuthActorType.WID) return false
                actor as WIDActor

                // Admins can access all directories
                if (isAdmin(actor.wid)) return true

                // Users have admin access over their identity workspaces and their corresponding
                // key directories
                if (isKeysDirectory(actor.wid)) return true
                if (ownsPath(actor.wid)) return true
            }
            else -> return false
        }
        return false
    }

    private fun isKeysDirectory(wid: RandomID): Boolean { return path.toString() == "/ keys $wid" }

    private fun isAdmin(wid: RandomID): Boolean {
        val adminWID = resolveAddress(DBConn(), MAddress.fromString("admin/$gServerDomain")!!)
        if (adminWID == null)
            logError("isAdmin couldn't find the admin's workspace ID")
        return adminWID == wid
    }

    private fun ownsPath(wid: RandomID): Boolean {
        return path.toString().startsWith("/ wsp $wid")
    }

    companion object {

        /**
         * Creates a DirectoryTarget object from the supplied path. Returns null if given a path
         * for a file.
         */
        fun fromPath(path: MServerPath): DirectoryTarget? {
            return if (path.isDir()) DirectoryTarget(path) else null
        }
    }
}