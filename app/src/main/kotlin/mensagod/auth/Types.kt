package mensagod.auth

import keznacl.toFailure
import libkeycard.MAddress
import libkeycard.RandomID
import mensagod.DBConn
import mensagod.dbcmds.resolveAddress
import mensagod.gServerDomain
import mensagod.logError
import java.net.InetAddress

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
open class WIDActor(val wid: RandomID) : AuthActor {
    override fun getType(): AuthActorType {
        return AuthActorType.WID
    }

    override fun toString(): String {
        return wid.toString()
    }

    fun isAdmin(): Result<Boolean> {
        val adminWID = resolveAddress(DBConn(), MAddress.fromString("admin/$gServerDomain")!!)
            .getOrElse { return it.toFailure() }
        if (adminWID == null)
            logError("isAdmin couldn't find the admin's workspace ID")
        return Result.success(adminWID == wid)
    }
}

/**
 * The SessionActor class represents more than just a workspace ID as a security context. It also
 * provides an IP address for the specific session.
 */
class SessionActor(wid: RandomID, val ip: InetAddress) : WIDActor(wid)

/**
 * The AuthAction class represents an action or group of actions as defined by the permissions
 * subsystem. The actions are performed by AuthActor entities on resources identified as an
 * AuthTarget. AuthAction is intended to be subclassed to represent specific actions.
 */
enum class AuthAction {
    // These are mostly for filesystem entries, but are general enough for other things, too.
    Create,
    Delete,
    Read,
    Modify,

    Access,         // For directory traversal and contents listing

    Register,       // account self-provisioning
    Preregister,    // provisioning an account on another's behalf
    Unregister,     // deprovisioning account, on another's behalf or self-deprovisioning
}

/**
 * The AuthTarget class represents a resource to be acted upon by an AuthActor. It, too, is also
 * intended to be subclassed to represent specific types of targets.
 */
interface AuthTarget {
    fun getActions(actor: AuthActor, action: AuthAction): Result<List<AuthAction>>
    fun isAuthorized(actor: AuthActor, action: AuthAction): Result<Boolean>
}
