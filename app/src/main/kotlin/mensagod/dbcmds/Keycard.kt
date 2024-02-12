package mensagod.dbcmds

import libkeycard.*
import mensagod.DBConn
import mensagod.DatabaseCorruptionException
import mensagod.NotConnectedException

/**
 * Adds an entry to the database. The caller is responsible for validation of the entry passed to
 * this command.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun addEntry(db: DBConn, entry: Entry) {
    val owner = if (entry.getFieldString("Type") == "Organization") "organization"
        else entry.getFieldString("Workspace-ID")!!

    db.execute("""INSERT INTO keycards(owner, creationtime, index, entry, fingerprint)
        VALUES(?,?,?,?,?)""",
        owner, entry.getFieldString("Timestamp")!!,
        entry.getFieldInteger("Index")!!, entry.getFullText(null).getOrThrow(),
        entry.getAuthString("Hash")!!).getOrThrow()
}

/**
 * getEntries pulls one or more entries from the database. Because of its flexibility, this call
 * is a bit complicated. Entry indices start counting at 1.
 *
 * If you pass a null workspace ID, the call will return entries for the organization. If you pass a
 * non-null WID, the call will return entries for the specified workspace. If the workspace is not
 * found or the workspace does not have any entries uploaded yet, the call will return an empty
 * list.
 *
 * If you want the entire keycard, just specify the WID. If you want just the current entry, pass
 * a 0 as the startIndex. In the unlikely event that you want just a subset of the entries, specify
 * both startIndex and endIndex. There is no penalty for specifying an endIndex which is larger
 * than the index of the current entry on the keycard -- such instances will function as if null
 * were passed as the endIndex and all entries starting with startIndex will be returned.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun getEntries(db: DBConn, wid: RandomID?, startIndex: UInt = 1U, endIndex: UInt? = null):
        MutableList<String> {
    val owner = wid?.toString() ?: "organization"

    val out = mutableListOf<String>()
    if (startIndex == 0U) {
        val rs = db.query("""SELECT entry FROM keycards WHERE owner = ? 
            ORDER BY index DESC LIMIT 1""", owner).getOrThrow()
        if (!rs.next()) return out
        out.add(rs.getString("entry"))
        return out
    }

    val rs = if (endIndex != null) {
        if (endIndex < startIndex) return out

        db.query("""SELECT entry FROM keycards WHERE owner = ? AND index >= ?
            AND index <= ? ORDER BY index""", owner, startIndex.toInt(), endIndex.toInt())
            .getOrThrow()
    } else {
        // Given just a start index
        db.query("""SELECT entry FROM keycards WHERE owner = ? AND index >= ? """, owner,
            startIndex.toInt()).getOrThrow()
    }

    while (rs.next()) out.add(rs.getString("entry"))
    return out
}

fun isDomainLocal(db: DBConn, domain: Domain): Result<Boolean> {
    TODO("Implement isDomainLocal($db, $domain")
}

/**
 * resolveAddress returns the workspace ID corresponding to a Mensago address. It will return null
 * if the corresponding workspace ID could not be found.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun resolveAddress(db: DBConn, addr: MAddress): RandomID? {

    // If the address is a workspace address, all we have to do is confirm the workspace exists --
    // workspace IDs are unique across an organization, not just a domain.
    if (addr.userid.type == IDType.WorkspaceID) {
        if (db.exists("""SELECT wtype FROM workspaces WHERE wid=?""", addr.userid.value)
                .getOrThrow() ||
            db.exists("""SELECT wid FROM aliases WHERE wid=?""", addr.userid.value)
                .getOrThrow()) {
            return addr.userid.toWID()!!
        }
        return null
    }

    val rs = db.query("""SELECT wid FROM workspaces WHERE uid=?""", addr.userid.value)
        .getOrThrow()
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
    val rs = db.query("""SELECT domain FROM workspaces WHERE wid=?""", wid).getOrThrow()
    if (!rs.next()) return null

    val dom = Domain.fromString(rs.getString("domain"))
        ?: throw DatabaseCorruptionException("Bad domain '${rs.getString("domain")}' "+
            "for workspace ID $wid")
    return WAddress.fromParts(wid, dom)
}
