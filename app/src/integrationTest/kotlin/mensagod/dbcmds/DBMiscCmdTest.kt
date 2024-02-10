package mensagod.dbcmds

import libkeycard.RandomID
import mensagod.*
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

        // Note that one of the errors for Update.Create should be checking that the data points
        // to a file and not a directory. Creating a directory should be MkDir

        // TODO: Finish implementing test for addUpdateRecord()
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
        getEncryptionPair(db)
        getPrimarySigningPair(db)
    }
}