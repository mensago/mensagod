package mensagod.dbcmds

import libkeycard.RandomID
import mensagod.*
import mensagod.fs.LocalFS

/**
 * Helper function for adding a quota record to the database.
 */
private fun addQuotaFromDisk(db: DBConn, wid: RandomID): Result<Pair<Long, Long>> {
    val usage = LocalFS.get().getDiskUsage(MServerPath("/ wsp $wid"))
        .getOrElse { return Result.failure(it) }
    val defaultQuota = ServerConfig.get().getInteger("global.default_quota")!! * 1_048_576L

    db.execute("INSERT INTO quotas(wid, usage, quota) VALUES(?,?,?)", wid, usage,
        defaultQuota).getOrElse { return Result.failure(it) }
    return Result.success(Pair(usage, defaultQuota))
}

/**
 * Returns a pair of integers representing the current disk usage and quota size.
 *
 * @throws NotConnectedException Returned if not connected to the database
 * @throws java.sql.SQLException Returned for database problems, most likely either with your query
 * or with the connection
 */
fun getQuotaInfo(db: DBConn, wid: RandomID): Result<Pair<Long, Long>> {
    val rs = db.query("SELECT usage,quota FROM quotas WHERE wid=?", wid)
        .getOrElse { return Result.failure(it) }

    val widPath = MServerPath("/ wsp $wid")
    if (!rs.next()) { return addQuotaFromDisk(db, wid) }

    val dbUsage = rs.getLong("usage")
    val dbQuota = rs.getLong("quota")
    if (dbUsage >= 0) { return Result.success(Pair(dbUsage, dbQuota)) }

    // We got this far, which means that the usage has not yet been loaded since the server was
    // started.
    val fsUsage = LocalFS.get().getDiskUsage(widPath).getOrElse { return Result.failure(it) }
    setQuotaUsage(db, wid, fsUsage)?.let { return Result.failure(it) }

    return Result.success(Pair(fsUsage, dbQuota))
}

/**
 * Modifies the disk usage in the quota information by a relative amount specified in bytes. Note
 * that if the quota usage does not exist in the database or has not yet been loaded since the
 * server started, the size parameter will be ignored and quota usage will be set from actual usage
 * on disk.
 *
 * @throws NotConnectedException Returned if not connected to the database
 * @throws java.sql.SQLException Returned for database problems, most likely either with your query
 * or with the connection
 */
fun modifyQuotaUsage(db: DBConn, wid: RandomID, size: Long): Result<Long> {
    val rs = db.query("SELECT usage FROM quotas WHERE wid=?", wid)
        .getOrElse { return Result.failure(it) }

    if (!rs.next()) {
        val info = addQuotaFromDisk(db, wid).getOrElse { return Result.failure(it) }
        return Result.success(info.first)
    }

    // Disk usage is lazily updated after each boot. If it has yet to be updated, the value in the
    // database will be negative
    val dbUsage = rs.getLong("usage")
    if (dbUsage < 0) {
        val usage = LocalFS.get().getDiskUsage(MServerPath("/ wsp $wid"))
            .getOrElse { return Result.failure(it) }
        setQuotaUsage(db, wid, usage)?.let { return Result.failure(it) }
        return Result.success(usage)
    }

    val newTotal = dbUsage + size
    setQuotaUsage(db, wid, newTotal)?.let { return Result.failure(it) }
    return Result.success(newTotal)
}

/**
 * Resets the disk quota usage count in the database for all workspaces, forcing it to be
 * recalculated.
 *
 * @throws NotConnectedException Returned if not connected to the database
 * @throws java.sql.SQLException Returned for database problems, most likely either with your query
 * or with the connection
 */
fun resetQuotaUsage(db: DBConn): Throwable? {
    return db.execute("UPDATE quotas SET usage=-1").exceptionOrNull()
}

/**
 * Sets the disk quota for a workspace to the specified number of bytes.
 *
 * @throws NotConnectedException Returned if not connected to the database
 * @throws java.sql.SQLException Returned for database problems, most likely either with your query
 * or with the connection
 * @throws ResourceNotFoundException Returned if the workspace doesn't exist
 */
fun setQuota(db: DBConn, wid: RandomID, quota: Int): Throwable? {
    val rows = db.execute("UPDATE quotas SET quota=? WHERE wid=?", quota, wid)
        .getOrElse { return it }

    // We made a change, so we're done here
    if (rows != null) return null

    // No change made, so we need to update things
    val lfs = LocalFS.get()
    val userWidPath = MServerPath("/ wsp $wid")
    val handle = lfs.entry(userWidPath)
    if (!handle.exists().getOrElse { return it }) {
        // If the directory for a workspace doesn't exist, check to see if it's at least an
        // actual workspace somewhere in the system
        val status = try { checkWorkspace(db, wid) } catch (e: Exception) { return e }
        if (status == null) return ResourceNotFoundException()
    }
    val usage = lfs.getDiskUsage(userWidPath).getOrElse { return it }
    return db.execute("INSERT INTO quotas(wid, usage, quota) VALUES(?,?,?)", wid, usage, quota)
        .exceptionOrNull()
}

/**
 * Sets the disk quota for a workspace to the specified number of bytes. If the usage has not been
 * updated since boot, the total is ignored and the actual value from disk is used.
 *
 * @throws NotConnectedException Returned if not connected to the database
 * @throws java.sql.SQLException Returned for database problems, most likely either with your query
 * or with the connection
 */
fun setQuotaUsage(db: DBConn, wid: RandomID, usage: Long): Throwable? {
    TODO("Implement setQuota($db, $wid, $usage)")
}
