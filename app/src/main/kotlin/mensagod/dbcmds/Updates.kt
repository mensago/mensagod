package mensagod.dbcmds

import keznacl.BadValueException
import keznacl.CryptoString
import keznacl.toFailure
import keznacl.toSuccess
import libkeycard.EntryTypeException
import libkeycard.RandomID
import libmensago.MServerPath
import mensagod.DBConn
import mensagod.DatabaseCorruptionException
import mensagod.ServerConfig
import java.time.Instant

class UpdateRecord(val id: RandomID, val type: UpdateType, val data: String, val time: String,
                   val devid: RandomID)

/**
 * Adds a record to the update table.
 *
 * @throws BadValueException Returned if the record's data is invalid for the update type
 * @throws EntryTypeException Returned if there is a typing problem in the record's data field, such
 * as a directory being given for a Create update record.

 * @see UpdateRecord
 */
fun addUpdateRecord(db: DBConn, wid: RandomID, rec: UpdateRecord): Throwable? {

    val parseSplitPath = fun (s: String): Pair<MServerPath, MServerPath>? {
        val parts = s.split(":", limit = 2)
        if (parts.size != 2) return null

        val pathOne = MServerPath.fromString(parts[0]) ?: return null
        val pathTwo = MServerPath.fromString(parts[1]) ?: return null
        return Pair(pathOne,pathTwo)
    }

    when (rec.type) {
        UpdateType.Create, UpdateType.Delete, UpdateType.Rotate -> {
            val filePath = MServerPath.fromString(rec.data)
                ?: return BadValueException("Invalid path in ${rec.type} record")
            if (filePath.isDir()) return EntryTypeException()
        }
        UpdateType.Mkdir -> {
            val parts = rec.data.split(":", limit = 2)
            val dirPath = MServerPath.fromString(parts[0])

            if (parts.size != 2 || dirPath == null || CryptoString.fromString(parts[1]) == null)
                return BadValueException("Invalid data in ${rec.type} record")
            if (dirPath.isFile()) return EntryTypeException()
        }
        UpdateType.Move -> {
            val pathPair = parseSplitPath(rec.data)
                ?: return BadValueException("Invalid data in ${rec.type} record")

            if (pathPair.first.isDir() || pathPair.second.isFile()) return EntryTypeException()
        }
        UpdateType.Replace -> {
            val pathPair = parseSplitPath(rec.data)
                ?: return BadValueException("Invalid data in ${rec.type} record")

            if (pathPair.first.isDir() || pathPair.second.isDir()) return EntryTypeException()
        }
        UpdateType.Rmdir -> {
            val dirPath = MServerPath.fromString(rec.data)
                ?: return BadValueException("Invalid path in ${rec.type} record")
            if (dirPath.isFile()) return EntryTypeException()
        }
    }

    val now = System.currentTimeMillis() / 1000L
    return db.execute("""INSERT INTO updates(rid,wid,update_type,update_data,unixtime,devid)
        VALUES(?,?,?,?,?,?)""",
        rec.id, wid, rec.type, rec.data, now, rec.devid)
        .exceptionOrNull()
}

/**
 * Returns the number of sync records which occurred after the specified time with a maximum of 1000
 *
 * @throws BadValueException Returned if unixtime is negative
 */
fun countSyncRecords(db: DBConn, wid: RandomID, unixtime: Long): Result<Int> {
    if (unixtime < 0) return BadValueException().toFailure()

    val rs = db.query(
        "SELECT COUNT(wid) FROM updates WHERE wid=? AND unixtime > ?", wid,
        unixtime
    ).getOrElse { return it.toFailure() }
    var out = 0
    while (rs.next()) out++
    return out.toSuccess()
}

/**
 * Clears out old sync records older than the amount of time specified in the server config.
 *
 * @exception BadValueException Returned if the max sync age could not be obtained from the server
 * config
 */
fun cullOldSyncRecords(db: DBConn, wid: RandomID): Throwable? {
    val unixtime = Instant.now().epochSecond
    val maxDays = ServerConfig.get().getInteger("performance.max_sync_age")
        ?: return BadValueException()
    val threshold = unixtime - (maxDays.toLong() * 86400)
    return db.execute("DELETE FROM updates WHERE unixtime - ? > 0", threshold).exceptionOrNull()
}

/**
 * Gets all update records after a specified period of time up to a maximum of 1000.
 */
fun getSyncRecords(db: DBConn, wid: RandomID, unixtime: Long): Result<List<UpdateRecord>> {
    if (unixtime < 0) return BadValueException().toFailure()

    val rs = db.query(
        "SELECT rid,update_type,update_data,unixtime,devid FROM updates WHERE wid=? " +
                "AND unixtime > ? ORDER BY rowid LIMIT 1000", wid, unixtime
    )
        .getOrElse { return it.toFailure() }
    val out = mutableListOf<UpdateRecord>()
    while (rs.next()) {
        val id = RandomID.fromString(rs.getString("rid"))
            ?: return DatabaseCorruptionException("Invalid update ID").toFailure()
        val type = UpdateType.fromString(rs.getString("update_type"))
            ?: return DatabaseCorruptionException("Invalid update type").toFailure()
        val devid = RandomID.fromString(rs.getString("devid"))
            ?: return DatabaseCorruptionException("Invalid device ID").toFailure()

        out.add(
            UpdateRecord(
                id, type, rs.getString("update_data"), rs.getString("unixtime"),
                devid
            )
        )
    }
    return out.toSuccess()
}

/**
 * The UpdateType enumerated class represents the different possible operations described by
 * UpdateRecord instances.
 */
enum class UpdateType {
    Create,
    Delete,
    Mkdir,
    Move,
    Replace,
    Rmdir,
    Rotate;

    override fun toString(): String {
        return when (this) {
            Create -> "create"
            Delete -> "delete"
            Mkdir -> "mkdir"
            Move -> "move"
            Replace -> "replace"
            Rmdir -> "rmdir"
            Rotate -> "rotate"
        }
    }

    companion object {

        fun fromString(s: String): UpdateType? {
            return when (s.lowercase()) {
                "create" -> Create
                "delete" -> Delete
                "mkdir" -> Mkdir
                "move" -> Move
                "replace" -> Replace
                "rmdir" -> Rmdir
                "rotate" -> Rotate
                else -> null
            }
        }

    }

}

