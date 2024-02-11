package mensagod.auth

import libkeycard.RandomID
import mensagod.MServerPath

/**
 * The FileTarget class is used for actions which operate on a file. Currently this is a very
 * simple system: admins can access everything and users can access everything in their own
 * workspace directories.
 *
 */
class FileTarget private constructor(private val path: MServerPath): AuthTarget {
    private val parent = path.parent()

    override fun getActions(actor: AuthActor, action: AuthAction): List<AuthAction> {
        if (actor.getType() != AuthActorType.WID) return listOf()
        actor as WIDActor

        if (actor.isAdmin() || isKeysDirectory(actor.wid) || ownsParent(actor.wid))
            return listOf(AuthAction.Create, AuthAction.Delete, AuthAction.Read, AuthAction.Modify)

        return listOf()
    }

    override fun isAuthorized(actor: AuthActor, action: AuthAction): Boolean {
        when (action) {
            AuthAction.Create, AuthAction.Delete, AuthAction.Read, AuthAction.Modify -> {
                if (actor.getType() != AuthActorType.WID) return false
                actor as WIDActor

                // Admins can access all directories and files
                if (actor.isAdmin()) return true

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