package mensagod.auth

import libkeycard.RandomID

/**
 * The WorkspaceTarget class represents an individual workspace identified by its workspace ID.
 * It is used for situations where an actor wants to perform an action on the workspace itself,
 * such as changing its status.
 */
class WorkspaceTarget(val wid: RandomID): AuthTarget {

    override fun isAuthorized(actor: AuthActor, action: AuthAction): Boolean {
        when (action) {
            else -> return false
        }
    }
}
