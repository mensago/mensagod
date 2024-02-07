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
    TODO("Implement dbcmds.getQuotaInfo")
}