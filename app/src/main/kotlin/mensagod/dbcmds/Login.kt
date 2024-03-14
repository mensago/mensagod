package mensagod.dbcmds

import keznacl.*
import libkeycard.*
import libmensago.NotConnectedException
import libmensago.ResourceExistsException
import libmensago.ResourceNotFoundException
import mensagod.DBConn
import mensagod.DatabaseCorruptionException

/**
 * checkPassword checks a password against the one stored in the database. It returns true if the
 * database's hash validates the password passed to the function.
 *
 * @throws ResourceNotFoundException if the workspace isn't found
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun checkPassword(db: DBConn, wid: RandomID, password: String): Result<Boolean> {
    val rs = db.query(
        """SELECT password FROM workspaces WHERE wid=? AND wtype='individual'""",
        wid
    ).getOrThrow()
    if (!rs.next()) return ResourceNotFoundException().toFailure()

    val hasher = Argon2idPassword()
    hasher.setFromHash(rs.getString("password"))?.let {
        return DatabaseCorruptionException("Bad argon2id hash for $wid").toFailure()
    }

    return hasher.verify(password).toSuccess()
}

/**
 * checkPassCode checks the validity of a workspace/passcode combination.
 *
 * @exception ExpiredException Returned if the reset code is expired
 * @exception NotConnectedException if not connected to the database
 * @exception java.sql.SQLException for database problems, most likely either with your query or
 * with the connection
 * @exception ResourceNotFoundException Returned if there is no reset code for the specified
 * workspace ID
 * @return true if authentication is successful
 */
fun checkPassCode(db: DBConn, wid: RandomID, resetCode: String): Result<Boolean> {
    val rs = db.query("SELECT passcode,expires FROM passcodes WHERE wid=?", wid)
        .getOrElse { return it.toFailure() }
    if (!rs.next())
        return ResourceNotFoundException().toFailure()

    TODO("Finish implementing checkPassCode($db, $wid, $resetCode)")
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
fun checkRegCode(db: DBConn, addr: MAddress, regcode: String): Result<Pair<RandomID, UserID?>?> {
    val rs = if (addr.isWorkspace) {
        db.query(
            """SELECT uid,regcode FROM prereg WHERE wid=? AND domain=?""",
            addr.userid, addr.domain
        ).getOrElse { return it.toFailure() }
    } else {
        db.query(
            """SELECT wid,regcode FROM prereg WHERE uid=? AND domain=?""",
            addr.userid, addr.domain
        ).getOrThrow()
    }
    if (!rs.next()) return Result.success(null)

    val rawHash = rs.getString("regcode")
    if (rawHash.isEmpty()) {
        return DatabaseCorruptionException(
            "Prereg entry missing regcode for workspace $addr"
        ).toFailure()
    }
    val regHash = Argon2idPassword()
    regHash.setFromHash(rawHash)?.let {
        return DatabaseCorruptionException(
            "Prereg entry has bad regcode for workspace $addr"
        ).toFailure()
    }
    if (!regHash.verify(regcode)) return Result.success(null)

    if (addr.isWorkspace) {
        val outUID = UserID.fromString(rs.getString("uid"))
        return Pair(addr.userid.toWID()!!, outUID).toSuccess()
    }

    val outWID = RandomID.fromString(rs.getString("wid"))
        ?: return DatabaseCorruptionException(
            "Bad prereg workspace ID ${rs.getString("wid")}"
        ).toFailure()
    return Pair(outWID, addr.userid).toSuccess()
}

/**
 * deletePrereg removes preregistration data from the database.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun deletePrereg(db: DBConn, addr: WAddress): Throwable? {
    return db.execute("DELETE FROM prereg WHERE wid=? AND domain=?", addr.id, addr.domain)
        .exceptionOrNull()
}

/**
 * Gets the password metadata for the specified workspace or null if not found.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun getPasswordInfo(db: DBConn, wid: RandomID): Result<PasswordInfo?> {
    val rs = db.query("""SELECT passtype,salt,passparams FROM workspaces WHERE wid=?""", wid)
        .getOrElse { return it.toFailure() }
    if (rs.next()) {
        val type = rs.getString("passtype")
        val salt = rs.getString("salt")
        val params = rs.getString("passparams")
        return PasswordInfo(type, salt, params).toSuccess()
    }
    return Result.success(null)
}

/**
 * preregWorkspace preregisters a workspace in the database.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 * @throws ResourceExistsException if the user ID or workspace ID given already exist.
 * @throws EmptyDataException if the registration code hash string is empty
 */
fun preregWorkspace(db: DBConn, wid: RandomID, userID: UserID?, domain: Domain, reghash: String):
        Throwable? {

    if (reghash.isEmpty())
        return EmptyDataException("registration code hash may not be empty")

    if (userID != null) {
        val resolvedWID = resolveUserID(db, userID).getOrElse { return it }
        if (resolvedWID != null)
            return ResourceExistsException("User-ID $userID already exists")
        val resolvedWAddr = resolveWID(db, wid).getOrElse { return it }
        if (resolvedWAddr != null)
            return ResourceExistsException("Workspcae-ID $wid already exists")

        return db.execute(
            """INSERT INTO prereg(wid, uid, domain, regcode) VALUES(?,?,?,?)""",
            wid, userID, domain, reghash
        ).exceptionOrNull()
    }

    if (resolveWID(db, wid).getOrElse { return it } != null)
        return ResourceExistsException("Workspace-ID $wid already exists")
    return db.execute(
        """INSERT INTO prereg(wid, domain, regcode) VALUES(?,?,?)""", wid, domain,
        reghash
    ).exceptionOrNull()
}

fun resetPassword(db: DBConn, resetCode: String, expires: Timestamp): Throwable? {
    TODO("Implement dbcmds.resetPassword($db, $resetCode, $expires")
}