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

    override fun getActions(actor: AuthActor, action: AuthAction): Result<List<AuthAction>> {
        if (actor.getType() != AuthActorType.WID) return Result.success(listOf())
        actor as WIDActor

        if (actor.isAdmin().getOrElse { return Result.failure(it) } ||
            isKeysDirectory(actor.wid) || ownsPath(actor.wid))
            return Result.success(listOf(AuthAction.Create, AuthAction.Delete, AuthAction.Access))

        return Result.success(listOf())
    }

    override fun isAuthorized(actor: AuthActor, action: AuthAction): Result<Boolean> {
        when (action) {
            AuthAction.Create, AuthAction.Delete, AuthAction.Access -> {
                if (actor.getType() != AuthActorType.WID) return Result.success(false)
                actor as WIDActor

                // Admins can access all directories
                if (actor.isAdmin().getOrElse { return Result.failure(it) })
                    return Result.success(true)

                // Users have admin access over their identity workspaces and their corresponding
                // key directories
                if (isKeysDirectory(actor.wid)) return Result.success(true)
                if (ownsPath(actor.wid)) return Result.success(true)
            }
            else -> return Result.success(false)
        }
        return Result.success(false)
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