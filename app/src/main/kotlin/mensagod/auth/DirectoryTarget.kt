package mensagod.auth

import libkeycard.RandomID
import libmensago.MServerPath

/**
 * The DirectoryTarget class is used for actions which operate on a directory.
 *
 * Admins have full access to the workspace hierarchy. Users have full access to their keys
 * directory and their own identity workspace directory hierarchy.
 *
 * Access allows an actor to view the contents of the directory and navigate into subdirectories
 * Create allows creation and modification of files and subdirectories
 * Delete allows the actor to delete files and subdirectories
 *
 * Currently only users are authorized directory target access.
 */
class DirectoryTarget private constructor(private val path: MServerPath): AuthTarget {

    override fun getActions(actor: AuthActor, action: AuthAction): List<AuthAction> {
        if (actor.getType() != AuthActorType.WID) return listOf()
        actor as WIDActor

        if (actor.isAdmin() || isKeysDirectory(actor.wid) || ownsPath(actor.wid))
            return listOf(AuthAction.Create, AuthAction.Delete, AuthAction.Access)

        return listOf()
    }

    override fun isAuthorized(actor: AuthActor, action: AuthAction): Boolean {
        when (action) {
            AuthAction.Create, AuthAction.Delete, AuthAction.Access -> {
                if (actor.getType() != AuthActorType.WID) return false
                actor as WIDActor

                // Admins can access all directories
                if (actor.isAdmin()) return true

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