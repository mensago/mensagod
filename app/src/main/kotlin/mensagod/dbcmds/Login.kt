package mensagod.dbcmds

import keznacl.EmptyDataException
import libkeycard.*
import mensagod.DBConn
import mensagod.NotConnectedException
import mensagod.ResourceExistsException

/**
 * preregWorkspace preregisters a workspace in the database.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 * @throws ResourceExistsException if the user ID or workspace ID given already exist.
 * @throws EmptyDataException if the registration code hash string is empty
 */
fun preregWorkspace(wid: RandomID, userID: UserID?, domain: Domain, reghash: String) {
    if (reghash.isEmpty())
        throw EmptyDataException("registration code hash may not be empty")

    val db = DBConn()

    if (userID != null) {
        if (resolveUserID(userID) != null)
            throw ResourceExistsException("User-ID $userID already exists")
        if (resolveWID(wid) != null)
            throw ResourceExistsException("Workspcae-ID $wid already exists")

        db.execute("""INSERT INTO prereg(wid, uid, domain, regcode) VALUES(?,?,?,?)""",
            wid, userID, domain, reghash)
        return
    }

    if (resolveWID(wid) != null)
        throw ResourceExistsException("Workspace-ID $wid already exists")
    db.execute("""INSERT INTO prereg(wid, domain, regcode) VALUES(?,?,?)""", wid, domain,
        reghash)
}

/**
 * deletePrereg removes preregistration data from the database.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun deletePrereg(addr: MAddress) {
    val db = DBConn()
    if (addr.userid.type == IDType.WorkspaceID) {
        db.execute("DELETE FROM prereg WHERE wid=? AND domain=? AND regcode=?", addr.userid,
            addr.domain)
    } else {
        db.execute("DELETE FROM prereg WHERE uid=? AND domain=? AND regcode=?", addr.userid,
            addr.domain)
    }
}
