package mensagod.dbcmds

import libkeycard.RandomID
import mensagod.DBConn
import mensagod.NotConnectedException

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

    TODO("Implement modifyQuotaUsage($wid, $size)")
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
    TODO("Implement resetQuotaUsage()")
}

/**
 * Sets the disk quota for a workspace to the specified number of bytes.
 *
 * @throws NotConnectedException Returned if not connected to the database
 * @throws java.sql.SQLException Returned for database problems, most likely either with your query
 * or with the connection
 */
fun setQuota(db: DBConn, wid: RandomID, quota: Int): Throwable? {
    TODO("Implement setQuota($db, $wid, $quota)")
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
