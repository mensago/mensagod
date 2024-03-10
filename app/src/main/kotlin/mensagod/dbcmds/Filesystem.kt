package mensagod.dbcmds

import keznacl.BadValueException
import keznacl.CryptoString
import keznacl.toFailure
import keznacl.toSuccess
import libkeycard.RandomID
import libmensago.MServerPath
import libmensago.NotConnectedException
import libmensago.ResourceNotFoundException
import mensagod.DBConn
import mensagod.LocalFS
import mensagod.ServerConfig
import java.io.IOException

/**
 * Adds a mapping of a server path to an encrypted client path.
 *
 * @exception BadValueException Returned if given a bad path
 * @exception NotConnectedException Returned if not connected to the database
 */
fun addFolderEntry(db: DBConn, wid: RandomID, serverPath: MServerPath, clientPath: CryptoString):
        Throwable? {
    db.execute(
        "DELETE FROM iwkspc_folders WHERE wid=? AND serverpath=?", wid, serverPath
    ).onFailure { return it }
    return db.execute(
        "INSERT INTO iwkspc_folders(wid, serverpath, clientpath) " +
                "VALUES(?,?,?)", wid, serverPath, clientPath
    ).exceptionOrNull()
}

/**
 * Returns a pair of integers representing the current disk usage and quota size.
 *
 * @exception ResourceNotFoundException Returned if the workspace doesn't exist
 * @exception IOException Returned if an I/O error occurs getting disk usage
 * @exception BadValueException Returned if given a bad path
 * @exception SecurityException Returned if a security manager exists and denies read access to the
 * file or directory
 * @exception NotConnectedException if not connected to the database
 * @exception java.sql.SQLException for database problems, most likely either with your query or
 * with the connection
 */
fun getQuotaInfo(db: DBConn, wid: RandomID): Result<Pair<Long, Long>> {
    val rs = db.query("SELECT usage,quota FROM quotas WHERE wid=?", wid)
        .getOrElse { return it.toFailure() }

    val widPath = MServerPath("/ wsp $wid")
    if (!rs.next()) {
        return addQuotaFromDisk(db, wid)
    }

    val dbUsage = rs.getLong("usage")
    val dbQuota = rs.getLong("quota")
    if (dbUsage >= 0) {
        return Pair(dbUsage, dbQuota).toSuccess()
    }

    // We got this far, which means that the usage has not yet been loaded since the server was
    // started.
    val fsUsage = LocalFS.get().getDiskUsage(widPath).getOrElse { return it.toFailure() }
    setQuotaUsage(db, wid, fsUsage)?.let { return it.toFailure() }

    return Pair(fsUsage, dbQuota).toSuccess()
}

/**
 * Modifies the disk usage in the quota information by a relative amount specified in bytes. Note
 * that if the quota usage does not exist in the database or has not yet been loaded since the
 * server started, the size parameter will be ignored and quota usage will be set from actual usage
 * on disk.
 *
 * @exception ResourceNotFoundException Returned if the workspace doesn't exist
 * @exception IOException Returned if an I/O error occurs getting disk usage
 * @exception BadValueException Returned if given a bad path
 * @exception SecurityException Returned if a security manager exists and denies read access to the
 * file or directory
 * @exception NotConnectedException if not connected to the database
 * @exception java.sql.SQLException for database problems, most likely either with your query or with
 * the connection
 */
fun modifyQuotaUsage(db: DBConn, wid: RandomID, size: Long): Result<Long> {
    val rs = db.query("SELECT usage FROM quotas WHERE wid=?", wid)
        .getOrElse { return it.toFailure() }

    if (!rs.next()) {
        val info = addQuotaFromDisk(db, wid).getOrElse { return it.toFailure() }
        return info.first.toSuccess()
    }

    // Disk usage is lazily updated after each boot. If it has yet to be updated, the value in the
    // database will be negative
    val dbUsage = rs.getLong("usage")
    if (dbUsage < 0) {
        val usage = LocalFS.get().getDiskUsage(MServerPath("/ wsp $wid"))
            .getOrElse { return it.toFailure() }
        setQuotaUsage(db, wid, usage)?.let { return it.toFailure() }
        return usage.toSuccess()
    }

    val newTotal = dbUsage + size
    setQuotaUsage(db, wid, newTotal)?.let { return it.toFailure() }
    return newTotal.toSuccess()
}

/**
 * Resets the disk quota usage count in the database for all workspaces, forcing it to be
 * recalculated.
 *
 * @exception NotConnectedException Returned if not connected to the database
 * @exception java.sql.SQLException Returned for database problems, most likely either with your query
 * or with the connection
 */
fun resetQuotaUsage(db: DBConn): Throwable? {
    return db.execute("UPDATE quotas SET usage=-1").exceptionOrNull()
}

/**
 * Sets the disk quota for a workspace to the specified number of bytes.
 *
 * @exception ResourceNotFoundException Returned if the workspace doesn't exist
 * @exception IOException Returned if an I/O error occurs getting disk usage
 * @exception BadValueException Returned if given a bad path
 * @exception SecurityException Returned if a security manager exists and denies read access to the
 * file or directory
 * @exception NotConnectedException if not connected to the database
 * @exception java.sql.SQLException for database problems, most likely either with your query or with
 * the connection
 */
fun setQuota(db: DBConn, wid: RandomID, quota: Long): Throwable? {
    val rows = db.execute("UPDATE quotas SET quota=? WHERE wid=?", quota, wid)
        .getOrElse { return it }

    // If we made a change, we're done here
    if ((rows ?: -1) > 0) return null

    addQuotaFromDisk(db, wid).getOrElse { return it }
    return db.execute("UPDATE quotas SET quota=? WHERE wid=?", quota, wid).exceptionOrNull()
}

/**
 * Sets the disk quota for a workspace to the specified number of bytes. If the usage has not been
 * updated since boot, the total is ignored and the actual value from disk is used.
 *
 * @exception ResourceNotFoundException Returned if the workspace doesn't exist
 * @exception IOException Returned if an I/O error occurs getting disk usage
 * @exception BadValueException Returned if given a bad path
 * @exception SecurityException Returned if a security manager exists and denies read access to the
 * file or directory
 * @exception NotConnectedException if not connected to the database
 * @exception java.sql.SQLException for database problems, most likely either with your query or with
 * the connection
 */
fun setQuotaUsage(db: DBConn, wid: RandomID, usage: Long): Throwable? {
    val rows = db.execute("UPDATE quotas SET usage=? WHERE wid=?", usage, wid)
        .getOrElse { return it }

    // If we made a change, we're done here
    if (rows != null) return null

    return addQuotaFromDisk(db, wid).exceptionOrNull()
}

/**
 * Helper function for adding a quota record to the database.
 *
 * @exception ResourceNotFoundException Returned if the workspace doesn't exist
 * @exception IOException Returned if an I/O error occurs getting disk usage
 * @exception BadValueException Returned if given a bad path
 * @exception SecurityException Returned if a security manager exists and denies read access to the
 * file or directory
 * @exception NotConnectedException if not connected to the database
 * @exception java.sql.SQLException for database problems, most likely either with your query or with
 * the connection
 */
private fun addQuotaFromDisk(db: DBConn, wid: RandomID): Result<Pair<Long, Long>> {
    val userWidPath = MServerPath("/ wsp $wid")
    val handle = LocalFS.get().entry(userWidPath)
    val usage = if (!handle.exists().getOrElse { return it.toFailure() }) {
        val status = checkWorkspace(db, wid).getOrElse { return it.toFailure() }
        if (status == null) return ResourceNotFoundException().toFailure()
        0
    } else {
        LocalFS.get().getDiskUsage(MServerPath("/ wsp $wid"))
            .getOrElse { return it.toFailure() }
    }

    val defaultQuota = ServerConfig.get().getInteger("global.default_quota")!! * 1_048_576L

    db.execute(
        "INSERT INTO quotas(wid, usage, quota) VALUES(?,?,?)", wid, usage,
        defaultQuota
    ).getOrElse { return it.toFailure() }
    return Pair(usage, defaultQuota).toSuccess()
}

