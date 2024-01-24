package mensagod.dbcmds

import keznacl.EmptyDataException
import libkeycard.*
import mensagod.DBConn
import mensagod.DatabaseCorruptionException
import mensagod.NotConnectedException
import mensagod.ResourceExistsException

/**
 * checkRegCode handles authenticating a host using a userID/workspaceID and registration code
 * provided by preregWorkspace(). Based on authentication, it either returns a Pair containing the
 * workspace ID and the user ID (if it exists) or null on failure. This call is responsible for
 * authentication only and does not perform any other registration-related tasks.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun checkRegCode(db: DBConn, addr: MAddress, regcode: String): Pair<RandomID, UserID?>? {
    if (addr.isWorkspace) {
        val rs = db.query("""SELECT uid FROM prereg WHERE regcode=? AND wid=? AND domain=?""",
            regcode, addr.userid, addr.domain)
        if (!rs.next()) return null

        val outUID = UserID.fromString(rs.getString("uid"))
        return Pair(addr.userid.toWID()!!, outUID)
    }

    val rs = db.query("""SELECT wid FROM prereg WHERE regcode=? AND uid=? AND domain=?""",
        regcode, addr.userid, addr.domain)
    if (!rs.next()) return null

    val outWID = RandomID.fromString(rs.getString("wid"))
        ?: throw DatabaseCorruptionException(
            "Bad prereg workspace ID ${rs.getString("wid")}")
    return Pair(outWID, addr.userid)
}

/**
 * deletePrereg removes preregistration data from the database.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun deletePrereg(db: DBConn, addr: MAddress) {
    if (addr.userid.type == IDType.WorkspaceID)
        db.execute("DELETE FROM prereg WHERE wid=? AND domain=?", addr.userid, addr.domain)
    else
        db.execute("DELETE FROM prereg WHERE uid=? AND domain=?", addr.userid, addr.domain)
}

/**
 * preregWorkspace preregisters a workspace in the database.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 * @throws ResourceExistsException if the user ID or workspace ID given already exist.
 * @throws EmptyDataException if the registration code hash string is empty
 */
fun preregWorkspace(db: DBConn, wid: RandomID, userID: UserID?, domain: Domain, reghash: String) {
    if (reghash.isEmpty())
        throw EmptyDataException("registration code hash may not be empty")

    if (userID != null) {
        if (resolveUserID(db, userID) != null)
            throw ResourceExistsException("User-ID $userID already exists")
        if (resolveWID(db, wid) != null)
            throw ResourceExistsException("Workspcae-ID $wid already exists")

        db.execute("""INSERT INTO prereg(wid, uid, domain, regcode) VALUES(?,?,?,?)""",
            wid, userID, domain, reghash)
        return
    }

    if (resolveWID(db, wid) != null)
        throw ResourceExistsException("Workspace-ID $wid already exists")
    db.execute("""INSERT INTO prereg(wid, domain, regcode) VALUES(?,?,?)""", wid, domain,
        reghash)
}
