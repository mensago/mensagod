package mensagod.auth

import keznacl.toFailure
import keznacl.toSuccess
import libkeycard.RandomID
import mensagod.DBConn
import mensagod.dbcmds.checkWorkspace

/**
 * The WorkspaceTarget class is used for actions which operate on workspaces themselves, such as
 * changing their status or unregistering them.
 */
class WorkspaceTarget private constructor(val wid: RandomID) : AuthTarget {

    override fun getActions(actor: AuthActor, action: AuthAction): Result<List<AuthAction>> {
        if (actor.getType() != AuthActorType.WID) return listOf<AuthAction>().toSuccess()
        actor as WIDActor

        if (actor.isAdmin().getOrElse { return it.toFailure() })
            return listOf(AuthAction.Modify, AuthAction.Archive).toSuccess()

        if (wid == actor.wid)
            return listOf(AuthAction.Archive).toSuccess()

        return listOf<AuthAction>().toSuccess()
    }

    override fun isAuthorized(actor: AuthActor, action: AuthAction): Result<Boolean> {
        return when (action) {
            AuthAction.Archive, AuthAction.Modify -> {
                if (actor.getType() != AuthActorType.WID) return false.toSuccess()
                actor as WIDActor
                (wid == actor.wid || actor.isAdmin().getOrElse { return it.toFailure() })
                    .toSuccess()
            }

            else -> false.toSuccess()
        }
    }

    companion object {

        fun fromWID(wid: RandomID): Result<WorkspaceTarget?> {
            val exists = checkWorkspace(DBConn(), wid).getOrElse { return it.toFailure() } != null
            return if (exists) WorkspaceTarget(wid).toSuccess() else Result.success(null)
        }
    }
}