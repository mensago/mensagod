package mensagod.dbcmds

import libkeycard.Domain
import libkeycard.RandomID
import libkeycard.UserID
import mensagod.DBConn
import mensagod.DatabaseCorruptionException
import mensagod.NotConnectedException
import mensagod.ResourceExistsException

enum class WorkspaceType {
    Individual;

    override fun toString(): String {
        return when (this) {
            Individual -> "individual"
        }
    }

    companion object {

        fun fromString(s: String): WorkspaceType? {
            return when (s.lowercase()) {
                "individual" -> Individual
                else -> null
            }
        }
    }
}

enum class WorkspaceStatus {
    Active,
    Approved,
    Archived,
    Disabled,
    Pending,
    Preregistered,
    Suspended,
    Unpaid;

    override fun toString(): String {
        return when (this) {
            Active -> "active"
            Approved -> "approved"
            Archived -> "archived"
            Disabled -> "disabled"
            Pending -> "pending"
            Preregistered -> "preregistered"
            Suspended -> "suspended"
            Unpaid -> "unpaid"
        }
    }

    companion object {

        fun fromString(s: String): WorkspaceStatus? {
            return when (s.lowercase()) {
                "active" -> Active
                "approved" -> Approved
                "archived" -> Archived
                "disabled" -> Disabled
                "pending" -> Pending
                "preregistered" -> Preregistered
                "suspended" -> Suspended
                "unpaid" -> Unpaid
                else -> null
            }
        }

    }
}

/**
 * addWorkspace is used for adding a workspace to the database. Other tasks related to provisioning
 * a workspace are not handled here.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 * @throws ResourceExistsException if the workspace ID already exists in the database
 */
fun addWorkspace(db: DBConn, wid: RandomID, uid: UserID?, domain: Domain, passhash: String,
                 algorithm: String, salt: String, passParams: String, status: WorkspaceStatus,
                 wtype: WorkspaceType) {

    val wStatus = checkWorkspace(db, wid)

    if (wStatus != null && wStatus != WorkspaceStatus.Preregistered)
        throw ResourceExistsException("$wid exists")
    db.execute("""INSERT INTO workspaces(wid, uid, domain, password, passtype, salt, passparams,
        status, wtype) VALUES(?,?,?,?,?,?,?,?,?)""",
        wid, uid ?: "", domain, passhash, algorithm, salt, passParams, status, wtype)
}

/**
 * checkWorkspace checks to see if a workspace exists. If it does exist, its status is returned. If
 * not, null is returned.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun checkWorkspace(db: DBConn, wid: RandomID): WorkspaceStatus? {
    var rs = db.query("""SELECT status FROM workspaces WHERE wid=?""", wid)
    if (rs.next()) {
        val stat = rs.getString("status")
        return WorkspaceStatus.fromString(stat)
            ?: throw DatabaseCorruptionException("Bad workspace status '$stat' for workspace $wid")
    }
    rs = db.query("""SELECT wid FROM prereg WHERE wid=?""", wid)
    if (rs.next())
        return WorkspaceStatus.Preregistered

    return null
}

/**
 * resolveUserID attempts to return the RandomID corresponding to the specified UserID. If it does
 * not exist, null is returned.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun resolveUserID(db: DBConn, uid: UserID): RandomID? {
    for (table in listOf("workspaces", "prereg")) {
        val rs = db.query("""SELECT wid FROM $table WHERE uid=?""", uid)
        if (rs.next()) {
            val widStr = rs.getString("wid")
            return RandomID.fromString(widStr)
                ?: throw DatabaseCorruptionException("Bad workspace ID '$widStr' for userID $uid")
        }
    }

    return null
}

/**
 * Sets the status of a workspace.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun setWorkspaceStatus(db: DBConn, wid: RandomID, status: WorkspaceStatus) {
    db.execute("""UPDATE workspaces SET status=? WHERE wid=?""", status, wid)
}
