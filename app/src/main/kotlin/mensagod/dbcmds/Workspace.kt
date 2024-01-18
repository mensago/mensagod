package mensagod.dbcmds

import libkeycard.RandomID
import libkeycard.UserID
import mensagod.DBConn
import mensagod.DatabaseCorruptionException
import mensagod.NotConnectedException

enum class WorkspaceStatus {
    Active,
    Pending,
    Blocked,
    Archived,
    Approved,
    Disabled;

    override fun toString(): String {
        return when (this) {
            Active -> "active"
            Pending -> "pending"
            Blocked -> "blocked"
            Archived -> "archived"
            Approved -> "approved"
            Disabled -> "disabled"
        }
    }

    companion object {

        fun fromString(s: String): WorkspaceStatus? {
            return when (s.lowercase()) {
                "active" -> Active
                "pending" -> Pending
                "blocked" -> Blocked
                "archived" -> Archived
                "approved" -> Approved
                "disabled" -> Disabled
                else -> null
            }
        }

    }
}

/**
 * checkWorkspace checks to see if a workspace exists. If it does exist, its status is returned. If
 * not, null is returned.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun checkWorkspace(wid: RandomID): WorkspaceStatus? {
    val db = DBConn()
    var rs = db.query("""SELECT status FROM workspaces WHERE wid=?""", wid)
    if (rs.next()) {
        val stat = rs.getString("status")
        return WorkspaceStatus.fromString(stat)
            ?: throw DatabaseCorruptionException("Bad workspace status '$stat' for workspace $wid")
    }
    rs = db.query("""SELECT wid FROM prereg WHERE wid=?""", wid)
    if (rs.next())
        return WorkspaceStatus.Approved

    return null
}

/**
 * resolveUserID attempts to return the RandomID corresponding to the specified UserID. If it does
 * not exist, null is returned.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun resolveUserID(uid: UserID): RandomID? {
    TODO("Implement resolveUserID")
}
