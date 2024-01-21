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
