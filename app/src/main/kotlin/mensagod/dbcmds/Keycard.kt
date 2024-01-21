package mensagod.dbcmds

import libkeycard.*
import mensagod.DBConn
import mensagod.DatabaseCorruptionException
import mensagod.NotConnectedException

/**
 * resolveAddress returns the workspace ID corresponding to a Mensago address.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun resolveAddress(addr: MAddress): RandomID? {

    val db = DBConn()

    // If the address is a workspace address, all we have to do is confirm the workspace exists --
    // workspace IDs are unique across an organization, not just a domain.
    if (addr.userid.type == IDType.WorkspaceID) {
        if (db.exists("""SELECT wtype FROM workspaces WHERE wid=?""", addr.userid.value) ||
            db.exists("""SELECT wid FROM aliases WHERE wid=?""", addr.userid.value))
            return addr.userid.toWID()!!
        return null
    }

    val rs = db.query("""SELECT wid FROM workspaces WHERE uid=?""", addr.userid.value)
    if (!rs.next()) return null

    return RandomID.fromString(rs.getString("wid"))
        ?: throw DatabaseCorruptionException("Bad wid '${rs.getString("wid")}' for address $addr")
}

/**
 * resolveWID returns a full workspace address given the workspace ID component
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun resolveWID(db: DBConn, wid: RandomID): WAddress? {
    val rs = db.query("""SELECT domain FROM workspaces WHERE wid=?""", wid)
    if (!rs.next()) return null

    val dom = Domain.fromString(rs.getString("domain"))
        ?: throw DatabaseCorruptionException("Bad domain '${rs.getString("domain")}' "+
            "for workspace ID $wid")
    return WAddress.fromParts(wid, dom)
}
