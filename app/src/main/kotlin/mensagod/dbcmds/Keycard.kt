package mensagod.dbcmds

import libkeycard.IDType
import libkeycard.MAddress
import libkeycard.RandomID
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
