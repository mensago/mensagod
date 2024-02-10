package mensagod.dbcmds

import keznacl.BadValueException
import keznacl.CryptoString
import libkeycard.RandomID
import mensagod.DBConn
import mensagod.MServerPath
import mensagod.TypeException
import java.util.regex.Pattern

private val movePattern = Pattern.compile(
"""^/( wsp| out| tmp)?( [0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12})*""" +
    """( new)?( [0-9]+\.[0-9]+\.""" +
    """[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12})*\s+""" +
    """/( wsp| out| tmp)?( [0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12})*""" +
    """( new)?$"""
).toRegex()

class UpdateRecord(val id: RandomID, val type: UpdateType, val data: String, val time: String,
                   val devid: RandomID)

/**
 * Adds a record to the update table
 */
fun addUpdateRecord(db: DBConn, wid: RandomID, rec: UpdateRecord): Throwable? {

    when (rec.type) {
        UpdateType.Create, UpdateType.Delete, UpdateType.RmDir -> {
            if (MServerPath.fromString(rec.data) == null)
                return BadValueException("Invalid path in ${rec.type} record")
        }
        UpdateType.Mkdir -> {
            val parts = rec.data.split(":", limit = 2)
            if (parts.size != 2 || MServerPath.fromString(parts[0]) == null ||
                CryptoString.fromString(parts[1]) == null) {
                return BadValueException("Invalid data in ${rec.type} record")
            }
        }
        UpdateType.Move -> {
            if (!movePattern.matches(rec.data))
                return BadValueException("Invalid data in ${rec.type} record")
        }
        else -> return TypeException("Bad record type")
    }

    val now = System.currentTimeMillis() / 1000L
    return db.execute("""INSERT INTO updates(rid,wid,update_type,update_data,unixtime,devid)
        VALUES(?,?,?,?,?,?)""",
        rec.id, wid, rec.type, rec.data, now, rec.devid)
        .exceptionOrNull()
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
    RmDir,
    Rotate;

    override fun toString(): String {
        return when (this) {
            Create -> "create"
            Delete -> "delete"
            Mkdir -> "mkdir"
            Move -> "move"
            Replace -> "replace"
            RmDir -> "rmdir"
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
                "rmdir" -> RmDir
                "roate" -> Rotate
                else -> null
            }
        }

    }

}

