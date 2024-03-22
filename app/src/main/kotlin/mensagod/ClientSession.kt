package mensagod

import keznacl.CryptoString
import keznacl.toFailure
import libkeycard.*
import libmensago.*
import mensagod.dbcmds.WorkspaceStatus
import mensagod.dbcmds.checkWorkspace
import mensagod.dbcmds.countSyncRecords
import mensagod.dbcmds.resolveAddress
import org.apache.commons.io.FileUtils
import java.io.RandomAccessFile
import java.net.Socket
import java.time.Instant

/** The LoginState class denotes where in the login process a client session is */
enum class LoginState {
    NoSession,
    AwaitingPassword,
    AwaitingDeviceID,
    LoggedIn,
}

open class SessionState(
    var message: ClientRequest = ClientRequest(""),
    var wid: RandomID? = null,
    var loginState: LoginState = LoginState.NoSession,
    var devid: RandomID? = null,
    var isTerminating: Boolean = false,
    var currentPath: MServerPath = MServerPath("/ wsp"),
)

/**
 * The ClientSession class encapsulates all the state needed for responding to requests during a
 * client-server connection session.
 */
class ClientSession(val conn: Socket) : SessionState() {

    private var lastUpdateCheck = Instant.now().epochSecond
    private var updateCount = 0

    /**
     * Handles setting up database connections for command handlers. Returns null if there was a
     * problem acquiring a connection to the database and has notified the client accordingly.
     */
    fun dbConnect(): DBConn? {
        return runCatching { DBConn() }.getOrElse {
            quickResponse(303, "SERVER UNAVAILABLE")
            null
        }
    }

    fun checkIfArchived(): Boolean {
        if (wid == null || loginState != LoginState.NoSession)
            return false

        val result = withDBResult { db ->
            checkWorkspace(db, wid!!).getOrNull() ?: run {
                db.disconnect()
                return false
            }
        }.getOrElse { return false }
        return result == WorkspaceStatus.Archived
    }

    /**
     * Checks the database for updates and update the session state update count.
     */
    fun checkForUpdates() {
        val now = Instant.now().epochSecond
        if (now - lastUpdateCheck < 3) return
        if (wid == null) return

        updateCount = withDBResult { db ->
            countSyncRecords(db, wid!!, now).getOrElse { db.disconnect(); return }
        }.getOrElse { return }
        lastUpdateCheck = now
    }

    /**
     * Validator function which gets a CryptoString from the specified field. All error states for
     * the field are handled internally, so if null is returned, the caller need not do anything
     * else. If the value is not required to be present, a default value may be specified, as well.
     */
    fun getCryptoString(field: String, required: Boolean, default: CryptoString? = null):
            CryptoString? {
        if (!message.hasField(field)) {
            return if (required) {
                quickResponse(400, "BAD REQUEST", "Required field missing: $field")
                null
            } else {
                default
            }
        }

        val cs = CryptoString.fromString(message.data[field]!!)
        if (cs == null) {
            quickResponse(400, "BAD REQUEST", "Bad $field")
            return null
        }
        return cs
    }

    /**
     * Validator function which gets a domain from the specified field. All error states for the
     * field are handled internally, so if null is returned, the caller need not do anything else.
     * If the value is not required to be present, a default value may be specified, as well.
     */
    fun getDomain(field: String, required: Boolean, default: Domain? = null): Domain? {
        if (!message.hasField(field)) {
            return if (required) {
                quickResponse(400, "BAD REQUEST", "Required field missing: $field")
                null
            } else {
                default
            }
        }

        val tempDom = Domain.fromString(message.data[field])
        if (tempDom == null) {
            quickResponse(400, "BAD REQUEST", "Bad $field")
            return null
        }
        return tempDom
    }

    /**
     * Validator function which gets an MServerPath from the specified field. All error states for
     * the field are handled internally, so if null is returned, the caller need not do anything
     * else. If the value is not required to be present, a default value may be specified, as well.
     */
    fun getPath(field: String, required: Boolean, default: MServerPath? = null): MServerPath? {
        if (!message.hasField(field)) {
            return if (required) {
                quickResponse(400, "BAD REQUEST", "Required field missing: $field")
                null
            } else {
                default
            }
        }

        val tempPath = MServerPath.fromString(message.data[field]!!)
        if (tempPath == null) {
            quickResponse(400, "BAD REQUEST", "Bad $field")
            return null
        }
        return tempPath
    }

    /**
     * Validator function which gets a user ID from the specified field. All error states for the
     * field are handled internally, so if null is returned, the caller need not do anything else.
     * If the value is not required to be present, a default value may be specified, as well.
     */
    fun getUserID(field: String, required: Boolean, default: UserID? = null): UserID? {
        if (!message.hasField(field)) {
            return if (required) {
                quickResponse(400, "BAD REQUEST", "Required field missing: $field")
                null
            } else {
                default
            }
        }

        val tempUID = UserID.fromString(message.data[field])
        if (tempUID == null) {
            quickResponse(400, "BAD REQUEST", "Bad $field")
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
                quickResponse(400, "BAD REQUEST", "Required field missing: $field")
                null
            } else {
                default
            }
        }

        val tempWID = RandomID.fromString(message.data[field])
        if (tempWID == null) {
            quickResponse(400, "BAD REQUEST", "Bad $field")
            return null
        }
        return tempWID
    }

    /**
     * Deprecated method which returns true if the local user has admin privileges.
     *
     * @throws NotConnectedException if not connected to the database
     * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
     */
    fun isAdmin(): Result<Boolean> {
        val adminWID = withDBResult { db ->
            resolveAddress(db, MAddress.fromString("admin/$gServerDomain")!!)
                .getOrElse { db.disconnect(); return it.toFailure() }
                ?: run {
                    db.disconnect()
                    return DatabaseCorruptionException(
                        "isAdmin couldn't find the admin's workspace ID"
                    ).toFailure()
                }
        }.getOrElse { return it.toFailure() }
        return Result.success(adminWID == wid)
    }

    /**
     * Static method which sends a basic message to the client. It suppresses network errors because
     * we're already in an error state.
     *
     * @throws kotlinx.serialization.SerializationException encoding-specific errors
     * @throws IllegalArgumentException if the encoded input does not comply format's specification
     */
    fun quickResponse(code: Int, status: String, info: String = ""): ClientSession {
        ServerResponse(code, status, info).sendCatching(
            conn,
            "Error sending quick response($code, $status, $info)"
        )
        return this
    }

    /**
     * Reads file data from a client and writes it directly to the file, optionally resuming from a
     * specified file offset.
     */
    fun readFileData(fileSize: Long, handle: LocalFSHandle, offset: Long?): Throwable? {
        var remaining = fileSize - (offset ?: 0)

        try {
            FileUtils.touch(handle.getFile())
            val rfile = RandomAccessFile(handle.getFile(), "rw")
            if (offset != null) rfile.seek(offset)

            val istream = conn.getInputStream()
            val buffer = ByteArray(65536)
            while (remaining > 0) {
                if (remaining < 65536) {
                    val lastChunk = istream.readNBytes(remaining.toInt())
                    rfile.write(lastChunk)
                    break
                }
                val bytesRead = istream.read(buffer)
                remaining -= bytesRead
                rfile.write(buffer)
            }
            rfile.close()
        } catch (e: Exception) {
            return e
        }
        return null
    }

    /**
     * requireLogin() notifies the client that a login session is required and returns false. If
     * the session is logged in, it returns true.
     */
    fun requireLogin(schema: Schema? = null): Boolean {
        if (loginState != LoginState.LoggedIn) {
            ServerResponse(401, "UNAUTHORIZED", "Login required")
                .sendCatching(conn, "requireLogin error message failure")
            return false
        }

        if (schema != null) {
            return schema.validate(message.data) { name, e ->
                val msg = if (e is MissingFieldException)
                    "Missing required field $name"
                else
                    "Bad value for field $name"
                quickResponse(400, "BAD REQUEST", msg)
            } ?: false
        }

        return true
    }

    /**
     * Convenience command used in command handlers to reduce the amount of boilerplate code needed
     * to handle potential internal errors.
     */
    fun internalError(logMsg: String, clientMsg: String): ClientSession {
        logError(logMsg)
        quickResponse(300, "INTERNAL SERVER ERROR", clientMsg)
        return this
    }

    /**
     * Reads file data from a file and sends it to a client, optionally resuming from a
     * specified file offset.
     */
    fun sendFileData(path: MServerPath, fileSize: Long, offset: Long): Throwable? {
        var remaining = fileSize - offset

        try {
            val lfs = LocalFS.get()
            val handle = lfs.entry(path)
            val rfile = RandomAccessFile(handle.getFile(), "r")
            rfile.seek(offset)

            val ostream = conn.getOutputStream()
            val buffer = ByteArray(65536)
            while (remaining > 0) {
                if (remaining < 65536) {
                    val lastChunkSize = rfile.read(buffer)
                    ostream.write(buffer, 0, lastChunkSize)
                    break
                }

                val bytesRead = rfile.read(buffer)
                remaining -= bytesRead
                ostream.write(buffer, 0, bytesRead)
            }

        } catch (e: Exception) {
            return e
        }
        return null
    }

    /**
     * Convenience command used in command handlers to reduce the amount of boilerplate code needed
     * to handle potential internal errors.
     */
    fun unavailableError(): ClientSession {
        quickResponse(303, "SERVER UNAVAILABLE")
        return this
    }

}
