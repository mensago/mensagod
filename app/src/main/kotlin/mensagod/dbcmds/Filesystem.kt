package mensagod.dbcmds

import libkeycard.RandomID
import mensagod.DBConn
import mensagod.MServerPath
import mensagod.NotConnectedException
import mensagod.ResourceNotFoundException
import mensagod.fs.LocalFS

/**
 * Returns a pair of integers representing the current disk usage and quota size.
 *
 * @throws NotConnectedException Returned if not connected to the database
 * @throws java.sql.SQLException Returned for database problems, most likely either with your query
 * or with the connection
 */
fun getQuotaInfo(db: DBConn, wid: RandomID): Result<Pair<Int, Int>> {
    TODO("Implement dbcmds.getQuotaInfo($db, $wid")
}

/**
 * Modifies the disk usage in the quota information by a relative amount specified in bytes.
 *
 * @throws NotConnectedException Returned if not connected to the database
 * @throws java.sql.SQLException Returned for database problems, most likely either with your query
 * or with the connection
 */
fun modifyQuotaUsage(db: DBConn, wid: RandomID, size: Int): Throwable? {

    TODO("Implement modifyQuotaUsage($db, $wid, $size)")
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
    TODO("Implement resetQuotaUsage($db)")
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
    var usage = 0L
    if (handle.exists().getOrElse { return it }) {
        usage = lfs.getDiskUsage(userWidPath).getOrElse { return it }
    } else {
        // If the directory for a workspace doesn't exist, check to see if it's at least an
        // actual workspace somewhere in the system
        val status = try { checkWorkspace(db, wid) } catch (e: Exception) { return e }
        if (status == null) return ResourceNotFoundException()
    }

    return db.execute("INSERT INTO quotas(wid, usge, quota) VALUES(?,?,?)", wid, usage, quota)
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
fun setQuotaUsage(db: DBConn, wid: RandomID, usage: Int): Throwable? {
    TODO("Implement setQuota($db, $wid, $usage)")
}
