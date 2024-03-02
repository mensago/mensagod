package mensagod.dbcmds

import keznacl.BadValueException
import libkeycard.EntryTypeException
import libkeycard.RandomID
import mensagod.DBConn
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import testsupport.ADMIN_PROFILE_DATA
import testsupport.setupTest
import testsupport.setupUser
import java.lang.Thread.sleep
import java.time.Instant
import java.util.*

class DBSyncCmdTest {

    @Test
    fun addSyncRecordTest() {
        setupTest("dbcmds.addSyncRecordTest")
        val db = DBConn()
        setupUser(db)

        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        val devid = RandomID.fromString(ADMIN_PROFILE_DATA["devid"])!!
        val unixTime = "12345678"
        val testDirID = RandomID.fromString("77d62128-4f94-432d-9e1b-4f5d6a2bd632")
        val testFileName =
            "${Instant.now().epochSecond}.1024.${UUID.randomUUID().toString().lowercase()}"

        val createID = RandomID.fromString("6dce4c07-dfbe-48ff-bc1a-cf3d2c33dd70")!!
        addSyncRecord(
            db, adminWID, SyncRecord(
                createID, UpdateType.Create, "/ wsp $adminWID $testFileName", unixTime, devid
            )
        )?.let { throw it }

        val rs = db.query("SELECT * FROM updates WHERE rid=?", createID).getOrThrow()
        assert(rs.next())
        assertEquals(adminWID.toString(), rs.getString("wid"))
        assertEquals(UpdateType.Create.toString(), rs.getString("update_type"))
        assertEquals("/ wsp $adminWID $testFileName", rs.getString("update_data"))
        rs.getString("unixtime").toLong()
        assertEquals(devid.toString(), rs.getString("devid"))

        // One of the error states for this method is if the record data points to the wrong type of
        // filesystem entry. For example, Create records are specifically for files, so it should
        // return an EntryTypeException -- reappropriated from keznacl here ;) -- if given data
        // which points to a directory.
        listOf(UpdateType.Create, UpdateType.Delete, UpdateType.Rotate).forEach {
            val result = addSyncRecord(
                db, adminWID, SyncRecord(
                    createID, it,
                    "/ wsp $adminWID $testDirID", unixTime, devid
                )
            )
            if (result !is EntryTypeException)
                throw Exception(
                    "Entry type checking failure for $it. Type returned: ${result?.javaClass}"
                )
        }

        assert(
            addSyncRecord(
                db, adminWID, SyncRecord(
                    RandomID.generate(), UpdateType.Mkdir,
                    "/ wsp $adminWID $testFileName:FOOBAR:abc12345", unixTime, devid
                )
            )
                    is EntryTypeException
        )

        assert(
            addSyncRecord(
                db, adminWID, SyncRecord(
                    RandomID.generate(), UpdateType.Move,
                    "/ wsp $adminWID $testFileName:/ $adminWID $testDirID $testFileName", unixTime,
                    devid
                )
            ) is EntryTypeException
        )

        assert(
            addSyncRecord(
                db, adminWID, SyncRecord(
                    RandomID.generate(), UpdateType.Rmdir,
                    "/ wsp $adminWID $testFileName", unixTime, devid
                )
            ) is EntryTypeException
        )
        assert(
            addSyncRecord(
                db, adminWID, SyncRecord(
                    RandomID.generate(), UpdateType.Replace,
                    "/ wsp $adminWID $testFileName:/ $adminWID $testDirID", unixTime,
                    devid
                )
            ) is EntryTypeException
        )
    }

    @Test
    fun getCountSyncRecordTest() {
        setupTest("dbcmds.getCountSync")
        val db = DBConn()
        setupUser(db)

        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        val devid = RandomID.fromString(ADMIN_PROFILE_DATA["devid"])!!
        val unixtime = 1_000_000L

        val recID1 = RandomID.fromString("11111111-1111-1111-1111-111111111111")!!
        var testFileName = "$unixtime.1024.${UUID.randomUUID().toString().lowercase()}"
        addSyncRecord(
            db, adminWID, SyncRecord(
                recID1, UpdateType.Create, "/ wsp $adminWID $testFileName", unixtime.toString(),
                devid
            )
        )?.let { throw it }

        val recID2 = RandomID.fromString("22222222-2222-2222-2222-222222222222")!!
        testFileName = "$unixtime.1024.${UUID.randomUUID().toString().lowercase()}"
        addSyncRecord(
            db, adminWID, SyncRecord(
                recID2, UpdateType.Create, "/ wsp $adminWID $testFileName",
                (unixtime + 10).toString(), devid
            )
        )?.let { throw it }

        sleep(1000)
        val recID3 = RandomID.fromString("33333333-3333-3333-3333-333333333333")!!
        testFileName = "$unixtime.1024.${UUID.randomUUID().toString().lowercase()}"
        addSyncRecord(
            db, adminWID, SyncRecord(
                recID3, UpdateType.Create, "/ wsp $adminWID $testFileName",
                (unixtime + 20).toString(), devid
            )
        )?.let { throw it }

        val fullList = getSyncRecords(db, adminWID, unixtime - 1).getOrThrow()
        if (fullList.size != 3) {
            println(fullList.joinToString("\n"))
            throw BadValueException()
        }
        val emptyList = getSyncRecords(db, adminWID, unixtime + 100).getOrThrow()
        if (emptyList.isNotEmpty()) {
            println(emptyList.joinToString("\n"))
            throw BadValueException()
        }
        assertEquals(unixtime, fullList[0].time.toLong())
        assertEquals(unixtime + 20, fullList[2].time.toLong())
        assert(getSyncRecords(db, adminWID, -1).exceptionOrNull() is BadValueException)

        assertEquals(3, countSyncRecords(db, adminWID, unixtime).getOrThrow())
        assertEquals(2, countSyncRecords(db, adminWID, unixtime + 5).getOrThrow())
        assertEquals(0, countSyncRecords(db, adminWID, unixtime + 100).getOrThrow())
        assert(countSyncRecords(db, adminWID, -1).exceptionOrNull() is BadValueException)
    }
}
