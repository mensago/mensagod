package mensagod.dbcmds

import libkeycard.RandomID
import mensagod.DBConn

enum class UpdateType {
    Create,
    Delete,
    Mkdir,
    Move,
    Replace,
    RmDir,
    Rotate
}

class UpdateRecord(id: RandomID, type: UpdateType, data: String, time: String, devid: RandomID)

/**
 * Adds a record to the update table
 */
fun addUpdateRecord(db: DBConn, wid: RandomID, rec: UpdateRecord): Throwable? {
    TODO("Implement addSyncRecord($db, $wid, $rec")
}
