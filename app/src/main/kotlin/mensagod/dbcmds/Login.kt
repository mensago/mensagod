package mensagod.dbcmds

import keznacl.Argon2idPassword
import keznacl.PasswordInfo
import keznacl.toFailure
import keznacl.toSuccess
import libkeycard.RandomID
import libkeycard.Timestamp
import libmensago.NotConnectedException
import libmensago.ResourceNotFoundException
import mensagod.DBConn
import mensagod.DatabaseCorruptionException
import mensagod.ExpiredException

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
fun checkResetCode(db: DBConn, wid: RandomID, resetCode: String): Result<Boolean> {
    val rs = db.query("SELECT resethash,expires FROM resetcodes WHERE wid=?", wid)
        .getOrElse { return it.toFailure() }
    if (!rs.next())
        return ResourceNotFoundException().toFailure()
    val expires = Timestamp.fromString(rs.getString("expires"))
        ?: return DatabaseCorruptionException("Bad timestamp found in resetcodes table").toFailure()
    if (expires.isAfter(Timestamp()))
        return ExpiredException().toFailure()
    val hasher = Argon2idPassword()
    hasher.setFromHash(rs.getString("resethash"))?.let {
        return DatabaseCorruptionException("Bad reset hash found in resetcodes table").toFailure()
    }
    return hasher.verify(resetCode).toSuccess()
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
 * Adds a hashed reset code to the table for the specified workspace. Only one reset code can be
 * active at a time; subsequent calls will delete old codes. Also, the resetHash here is expected to
 * be an Argon2idPassword hash.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun resetPassword(db: DBConn, wid: RandomID, resetHash: String, expires: Timestamp): Throwable? {
    db.execute("DELETE FROM resetcodes WHERE wid=?", wid).onFailure { return it }
    return db.execute(
        "INSERT INTO resetcodes(wid,resethash,expires) VALUES(?,?,?)", wid, resetHash,
        expires
    ).exceptionOrNull()
}

/**
 * Changes the password for a workspace. Note that the hashed password is expected to be given here,
 * not the cleartext password.
 */
fun setPassword(
    db: DBConn,
    wid: RandomID,
    passhash: String,
    algorithm: String,
    salt: String,
    params: String
): Throwable? {
    return db.execute(
        "UPDATE workspaces SET password=?,passtype=?,salt=?,passparams=? WHERE wid=?",
        passhash, algorithm, salt, params, wid
    ).exceptionOrNull()
}
