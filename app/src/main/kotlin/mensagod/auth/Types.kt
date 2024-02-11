package mensagod.auth

import libkeycard.RandomID

enum class AuthActorType {
    WID
}

/**
 * The AuthActor interface represents an actor for the permissions subsystem. This has not been
 * defined as a class for performance reasons.
 */
interface AuthActor {
    fun getType(): AuthActorType
}

/**
 * The WIDActor class represents a local user identified by its workspace ID. This actor is
 * typically used when the actor is either logging in or is already logged in.
 */
class WIDActor(val wid: RandomID): AuthActor {
    override fun getType(): AuthActorType { return AuthActorType.WID }
    override fun toString(): String { return wid.toString() }
}

/**
 * The AuthAction class represents an action or group of actions as defined by the permissions
 * subsystem. The actions are performed by AuthActor entities on resources identified as an
 * AuthTarget. AuthAction is intended to be subclassed to represent specific actions.
 */
enum class AuthAction {
    // These are mostly for filesystem entries, but are general enough for other things, too.
    Create,
    Delete,
    
    Register,       // account self-provisioning
    Preregister,    // provisioning an account on another's behalf
    Unregister,     // deprovisioning account, on another's behalf or self-deprovisioning
}

/**
 * The AuthTarget class represents a resource to be acted upon by an AuthActor. It, too, is also
 * intended to be subclassed to represent specific types of targets.
 */
interface AuthTarget {
    fun isAuthorized(actor: AuthActor, action: AuthAction): Boolean
}
