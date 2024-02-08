package mensagod.dbcmds

import keznacl.Argon2idPassword
import keznacl.EmptyDataException
import keznacl.PasswordInfo
import libkeycard.*
import mensagod.*

/**
 * checkPassword checks a password against the one stored in the database. It returns true if the
 * database's hash validates the password passed to the function.
 *
 * @throws ResourceNotFoundException if the workspace isn't found
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun checkPassword(db: DBConn, wid: RandomID, password: String): Boolean {
    val rs = db.query("""SELECT password FROM workspaces WHERE wid=?""", wid)
    if (!rs.next()) throw ResourceNotFoundException()

    val hasher = Argon2idPassword()
    hasher.setFromHash(rs.getString("password"))?.let {
        throw DatabaseCorruptionException("Bad argon2id hash for $wid")
    }

    return hasher.verify(password)
}

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
    val rs = if (addr.isWorkspace) {
        db.query(
            """SELECT uid,regcode FROM prereg WHERE wid=? AND domain=?""",
            addr.userid, addr.domain
        )
    } else {
        db.query("""SELECT wid,regcode FROM prereg WHERE uid=? AND domain=?""",
            addr.userid, addr.domain)
    }
    if (!rs.next()) return null

    val rawHash = rs.getString("regcode")
    if (rawHash.isEmpty()) {
        throw DatabaseCorruptionException(
            "Prereg entry missing regcode for workspace $addr")
    }
    val regHash = Argon2idPassword()
    regHash.setFromHash(rawHash)?.let {
        throw DatabaseCorruptionException(
            "Prereg entry has bad regcode for workspace $addr")
    }
    if (!regHash.verify(regcode)) return null

    if (addr.isWorkspace) {
        val outUID = UserID.fromString(rs.getString("uid"))
        return Pair(addr.userid.toWID()!!, outUID)
    }

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
fun deletePrereg(db: DBConn, addr: WAddress) {
    db.execute("DELETE FROM prereg WHERE wid=? AND domain=?", addr.id, addr.domain).getOrThrow()
}

/**
 * Gets the password metadata for the specified workspace or null if not found.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun getPasswordInfo(db: DBConn, wid: RandomID): PasswordInfo? {
    val rs = db.query("""SELECT passtype,salt,passparams FROM workspaces WHERE wid=?""", wid)
    if (rs.next()) {
        val type = rs.getString("passtype")
        val salt = rs.getString("salt")
        val params = rs.getString("passparams")
        return PasswordInfo(type, salt, params)
    }
    return null
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
            wid, userID, domain, reghash).getOrThrow()
        return
    }

    if (resolveWID(db, wid) != null)
        throw ResourceExistsException("Workspace-ID $wid already exists")
    db.execute("""INSERT INTO prereg(wid, domain, regcode) VALUES(?,?,?)""", wid, domain,
        reghash).getOrThrow()
}
