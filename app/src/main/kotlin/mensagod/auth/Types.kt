package mensagod.auth

import libkeycard.RandomID

/**
 * The AuthActor class represents an actor for the permissions subsystem. It is intended to be
 * subclassed for specific actor types.
 */
open class AuthActor

/**
 * The WIDActor class represents a local user identified by its workspace ID. This actor is
 * typically used when the actor is either logging in or is already logged in.
 */
class WIDActor(val wid: RandomID): AuthActor() {
    override fun toString(): String { return wid.toString() }
}

/**
 * The AuthAction class represents an action or group of actions as defined by the permissions
 * subsystem. The actions are performed by AuthActor entities on resources identified as an
 * AuthTarget. AuthAction is intended to be subclassed to represent specific actions.
 */
enum class AuthAction {
    Register,       // account self-provisioning
    Preregister,    // provisioning an account on another's behalf
    Unregister,     // deprovisioning account, on another's behalf or self-deprovisioning
}

/**
 * The AuthTarget class represents a resource to be acted upon by an AuthActor. It, too, is also
 * intended to be subclassed to represent specific types of targets.
 */
open class AuthTarget

/**
 * The WorkspaceTarget class represents a workspace identified by its workspace ID. It is used for
 * situations where an actor wants to perform an action on the workspace itself, such as changing
 * its status.
 */
class WorkspaceTarget(val wid: RandomID): AuthTarget()
