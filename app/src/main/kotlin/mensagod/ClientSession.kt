package mensagod

import libkeycard.*
import mensagod.commands.ClientRequest
import mensagod.commands.ServerResponse
import mensagod.dbcmds.resolveAddress
import java.net.Socket

/** The LoginState class denotes where in the login process a client session is */
enum class LoginState {
    NoSession,
    AwaitingPassword,
    AwaitingDeviceID,
    LoggedIn,
}

/**
 * The ClientSession class encapsulates all the state needed for responding to requests during a
 * client-server connection session.
 */
class ClientSession(val conn: Socket) {
    var passwordFailures = 0
    var loginState = LoginState.NoSession
    var isTerminating = false
    var wid: RandomID? = null
    var devid: RandomID? = null
    var message = ClientRequest("")

    /**
     * Validator function which gets a domain from the specified field. All error states for the
     * field are handled internally, so if null is returned, the caller need not do anything else.
     * If the value is not required to be present, a default value may be specified, as well.
     */
    fun getDomain(field: String, required: Boolean, default: Domain? = null): Domain? {
        if (!message.hasField(field)) {
            return if (required) {
                ServerResponse(400, "BAD REQUEST",
                    "Required field missing: $field").send(conn)
                return null
            } else {
                default
            }
        }

        val tempDom = Domain.fromString(message.data[field])
        if (tempDom == null) {
            ServerResponse(400, "BAD REQUEST", "Bad $field").send(conn)
            return null
        }
        return tempDom
    }

    /**
     * Validator function which gets a user ID from the specified field. All error states for the
     * field are handled internally, so if null is returned, the caller need not do anything else.
     * If the value is not required to be present, a default value may be specified, as well.
     */
    fun getUserID(field: String, required: Boolean, default: UserID? = null): UserID? {
        if (!message.hasField(field)) {
            return if (required) {
                ServerResponse(400, "BAD REQUEST",
                    "Required field missing: $field").send(conn)
                return null
            } else {
                default
            }
        }

        val tempUID = UserID.fromString(message.data[field])
        if (tempUID == null) {
            ServerResponse(400, "BAD REQUEST", "Bad $field").send(conn)
            return null
        }
        return tempUID
    }

    /**
     * Validator function which gets a RandomID from the specified field. All error states for the
     * field are handled internally, so if null is returned, the caller need not do anything else.
     * If the value is not required to be present, a default value may be specified, as well.
     */
    fun getRandomID(field: String, required: Boolean, default: RandomID? = null): RandomID? {
        if (!message.hasField(field)) {
            return if (required) {
                ServerResponse(400, "BAD REQUEST",
                    "Required field missing: $field").send(conn)
                return null
            } else {
                default
            }
        }

        val tempWID = RandomID.fromString(message.data[field])
        if (tempWID == null) {
            ServerResponse(400, "BAD REQUEST", "Bad $field").send(conn)
            return null
        }
        return tempWID
    }

    /**
     * requireLogin() notifies the client that a login session is required and returns false. If
     * the session is logged in, it returns true.
     */
    fun requireLogin(): Boolean {
        if (loginState != LoginState.LoggedIn) {
            ServerResponse(401, "UNAUTHORIZED", "Login required").send(conn)
            return false
        }

        return true
    }

    /**
     * requireAdminLogin() checks if the client is logged in with an account that has administrator
     * permissions and notifies the client if the session isn't.
     *
     * @throws DatabaseCorruptionException if the admin WID couldn't be found
     */
    fun requireAdminLogin(): Boolean {
        if (!requireLogin()) return false

        val admin = getAdmin()
        if (wid != admin.id) {
            ServerResponse(403, "FORBIDDEN", "Only admin can use this command")
                .send(conn)
            return false
        }
        return true
    }
}

/**
 * Returns the WID of the administrator account.
 *
 * @throws DatabaseCorruptionException if the admin WID couldn't be found
 */
fun getAdmin(): WAddress {
    val addr = MAddress.fromParts(UserID.fromString("admin")!!, gServerDomain)
    val wid = resolveAddress(addr)
        ?: throw DatabaseCorruptionException("Administrator WID missing from database")
    return WAddress.fromParts(wid, gServerDomain)
}
