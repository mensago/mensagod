package mensagod.auth

import keznacl.toFailure
import keznacl.toSuccess
import libkeycard.RandomID
import mensagod.dbcmds.checkWorkspace
import mensagod.withDBResult

/**
 * The WorkspaceTarget class is used for actions which operate on workspaces themselves, such as
 * changing their status or unregistering them.
 */
class WorkspaceTarget private constructor(val wid: RandomID) : AuthTarget {

    override fun getActions(actor: AuthActor, action: AuthAction): Result<List<AuthAction>> {
        if (actor.getType() != AuthActorType.WID) return listOf<AuthAction>().toSuccess()
        actor as WIDActor
        if (actor.isAdmin().getOrElse { return it.toFailure() })
            return listOf(
                AuthAction.Modify,
                AuthAction.Archive,
                AuthAction.GetQuota,
                AuthAction.SetQuota
            ).toSuccess()

        if (wid == actor.wid)
            return listOf(AuthAction.Modify, AuthAction.Archive, AuthAction.GetQuota).toSuccess()

        return listOf<AuthAction>().toSuccess()
    }

    override fun isAuthorized(actor: AuthActor, action: AuthAction): Result<Boolean> {
        if (actor.getType() != AuthActorType.WID) return false.toSuccess()
        actor as WIDActor
        val isAdmin = actor.isAdmin().getOrElse { return it.toFailure() }
        return when (action) {
            AuthAction.SetQuota -> isAdmin.toSuccess()
            AuthAction.Archive, AuthAction.Modify, AuthAction.GetQuota -> {
                (wid == actor.wid || isAdmin).toSuccess()
            }

            else -> false.toSuccess()
        }
    }

    companion object {

        fun fromWID(wid: RandomID): Result<WorkspaceTarget?> {
            val exists = withDBResult { db ->
                checkWorkspace(db, wid)
                    .getOrElse { db.disconnect(); return it.toFailure() } != null
            }.getOrElse { return it.toFailure() }
            return if (exists) WorkspaceTarget(wid).toSuccess() else Result.success(null)
        }
    }
}