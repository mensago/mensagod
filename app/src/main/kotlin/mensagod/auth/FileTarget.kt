package mensagod.auth

import keznacl.toFailure
import keznacl.toSuccess
import libkeycard.RandomID
import libmensago.MServerPath

/**
 * The FileTarget class is used for actions which operate on a file. Currently this is a very
 * simple system: admins can access everything and users can access everything in their own
 * workspace directories.
 *
 */
class FileTarget private constructor(private val path: MServerPath) : AuthTarget {
    private val parent = path.parent()

    override fun getActions(actor: AuthActor, action: AuthAction): Result<List<AuthAction>> {
        if (actor.getType() != AuthActorType.WID) return listOf<AuthAction>().toSuccess()
        actor as WIDActor

        if (actor.isAdmin().getOrElse { return it.toFailure() } ||
            isKeysDirectory(actor.wid) || ownsParent(actor.wid))
            return listOf(
                AuthAction.Create, AuthAction.Delete, AuthAction.Read, AuthAction.Modify
            ).toSuccess()

        return listOf<AuthAction>().toSuccess()
    }

    override fun isAuthorized(actor: AuthActor, action: AuthAction): Result<Boolean> {
        when (action) {
            AuthAction.Create, AuthAction.Delete, AuthAction.Read, AuthAction.Modify -> {
                if (actor.getType() != AuthActorType.WID) return false.toSuccess()
                actor as WIDActor

                // Admins can access all directories and files
                val isAdmin = actor.isAdmin().getOrElse { return it.toFailure() }
                if (isAdmin)
                    return true.toSuccess()

                // Users have admin access over their identity workspaces and their corresponding
                // key directories
                if (isKeysDirectory(actor.wid)) return true.toSuccess()
                if (ownsParent(actor.wid)) return true.toSuccess()
            }

            else -> return false.toSuccess()
        }
        return false.toSuccess()
    }

    private fun isKeysDirectory(wid: RandomID): Boolean {
        return path.toString() == "/ keys $wid"
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