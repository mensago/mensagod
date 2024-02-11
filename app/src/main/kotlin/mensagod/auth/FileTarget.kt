package mensagod.auth

import libkeycard.MAddress
import libkeycard.RandomID
import mensagod.DBConn
import mensagod.MServerPath
import mensagod.dbcmds.resolveAddress
import mensagod.gServerDomain
import mensagod.logError

/**
 * The FileTarget class is used for actions which operate on a file. Currently this is a very
 * simple system: admins can access everything and users can access everything in their own
 * workspace directories.
 *
 */
class FileTarget private constructor(private val path: MServerPath): AuthTarget {
    private val parent = path.parent()

    override fun isAuthorized(actor: AuthActor, action: AuthAction): Boolean {
        when (action) {
            AuthAction.Create, AuthAction.Delete, AuthAction.Read, AuthAction.Modify -> {
                if (actor.getType() != AuthActorType.WID) return false
                actor as WIDActor

                // Admins can access all directories and files
                if (isAdmin(actor.wid)) return true

                // Users have admin access over their identity workspaces and their corresponding
                // key directories
                if (isKeysDirectory(actor.wid)) return true
                if (ownsParent(actor.wid)) return true
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

    private fun ownsParent(wid: RandomID): Boolean {
        return parent.toString().startsWith("/ wsp $wid")
    }

    companion object {

        /**
         * Creates a FileTarget object from the supplied path. Returns null if given a path
         * for a directory.
         */
        fun fromPath(path: MServerPath): FileTarget? {
            return if (path.isFile()) FileTarget(path) else null
        }
    }
}