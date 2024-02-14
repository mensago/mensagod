package mensagod.dbcmds

import libkeycard.EntryTypeException
import libkeycard.RandomID
import mensagod.*
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.time.Instant
import java.util.*

class DBMiscCmdTest {

    @Test
    fun addUpdateRecordTest() {
        setupTest("dbcmds.addUpdateRecordTest")
        val db = DBConn()
        setupUser(db)

        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        val devid = RandomID.fromString(ADMIN_PROFILE_DATA["devid"])!!
        val unixTime = "12345678"
        val testDirID = RandomID.fromString("77d62128-4f94-432d-9e1b-4f5d6a2bd632")
        val testFileName =
            "${Instant.now().epochSecond}.1024.${UUID.randomUUID().toString().lowercase()}"

        val createID = RandomID.fromString("6dce4c07-dfbe-48ff-bc1a-cf3d2c33dd70")!!
        addUpdateRecord(db, adminWID, UpdateRecord(
            createID, UpdateType.Create,"/ wsp $adminWID $testFileName", unixTime, devid
        ))?.let { throw it }

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
            val result = addUpdateRecord(db, adminWID, UpdateRecord(createID, it,
                "/ wsp $adminWID $testDirID", unixTime, devid))
            if(result !is EntryTypeException)
                throw Exception(
                    "Entry type checking failure for $it. Type returned: ${result?.javaClass}")
        }

        assert(addUpdateRecord(db, adminWID, UpdateRecord(RandomID.generate(), UpdateType.Mkdir,
            "/ wsp $adminWID $testFileName:FOOBAR:abc12345", unixTime, devid))
                is EntryTypeException)

        assert(addUpdateRecord(db, adminWID, UpdateRecord(RandomID.generate(), UpdateType.Move,
            "/ wsp $adminWID $testFileName:/ $adminWID $testDirID $testFileName", unixTime,
            devid)) is EntryTypeException)

        assert(addUpdateRecord(db, adminWID, UpdateRecord(RandomID.generate(), UpdateType.Rmdir,
            "/ wsp $adminWID $testFileName", unixTime, devid)) is EntryTypeException)
        assert(addUpdateRecord(db, adminWID, UpdateRecord(RandomID.generate(), UpdateType.Replace,
            "/ wsp $adminWID $testFileName:/ $adminWID $testDirID", unixTime,
            devid)) is EntryTypeException)
    }

    @Test
    fun keypairTest() {
        val config = ServerConfig.load().getOrThrow()
        resetDB(config).getOrThrow()
        DBConn.initialize(config)?.let { throw it }
        val db = DBConn().connect().getOrThrow()
        initDB(db.getConnection()!!)

        // These methods will return the proper data or throw, so we don't have to do anything to
        // test them except call them. :)
        getEncryptionPair(db).getOrThrow()
        getPrimarySigningPair(db).getOrThrow()
    }
}