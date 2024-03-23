package mensagod.dbcmds

import keznacl.CryptoString
import libkeycard.RandomID
import libmensago.MServerPath
import mensagod.DBConn
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import testsupport.*
import java.nio.file.Paths

class DBFSCmdTest {

    @Test
    fun addRemoveFolderEntryTest() {
        setupTest("dbcmds.addRemoveFolderEntry")
        val db = DBConn()
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        val testPath = MServerPath("/ $adminWID d1a3b0f8-6180-4819-865e-7b687784ccf0")

        // Test Case #1: Success
        addFolderEntry(db, adminWID, testPath, CryptoString.fromString("XSALSA20:foobar")!!)
            ?.let { throw it }
        var rs = db.query("SELECT * from iwkspc_folders WHERE wid=?", adminWID).getOrThrow()
        assert(rs.next())
        assertEquals(adminWID.toString(), rs.getString("wid"))
        assertEquals(testPath.toString(), rs.getString("serverpath"))
        assertEquals("XSALSA20:foobar", rs.getString("clientpath"))

        // Test Case #2: Overwrite entry
        addFolderEntry(db, adminWID, testPath, CryptoString.fromString("XSALSA20:foobar2")!!)
            ?.let { throw it }
        rs = db.query("SELECT * from iwkspc_folders WHERE wid=?", adminWID).getOrThrow()
        assert(rs.next())
        assertEquals(adminWID.toString(), rs.getString("wid"))
        assertEquals(testPath.toString(), rs.getString("serverpath"))
        assertEquals("XSALSA20:foobar2", rs.getString("clientpath"))

        rs = db.query("SELECT COUNT(*) from iwkspc_folders WHERE wid=?", adminWID).getOrThrow()
        assert(rs.next())
        assertEquals(1, rs.getInt(1))

        // Test Case #3: Try to delete non-existent entry
        removeFolderEntry(
            db, RandomID.fromString("56f493d3-7d98-4d2d-b1a7-421349bb97dd")!!,
            testPath
        )?.let { throw it }
        rs = db.query("SELECT COUNT(*) from iwkspc_folders WHERE wid=?", adminWID).getOrThrow()
        assert(rs.next())
        assertEquals(1, rs.getInt(1))

        // Test Case #4: Try to delete non-existent entry
        removeFolderEntry(db, adminWID, testPath)?.let { throw it }
        rs = db.query("SELECT COUNT(*) from iwkspc_folders WHERE wid=?", adminWID).getOrThrow()
        assert(rs.next())
        assertEquals(0, rs.getInt(1))
        db.disconnect()
    }

    @Test
    fun getQuotaInfoTest() {
        val setupData = setupTest("dbcmds.getQuotaInfo")
        val db = DBConn()
        setupUser(db)

        val userWID = RandomID.fromString(USER_PROFILE_DATA["wid"])!!
        val userTopPath = Paths.get(setupData.testPath, "topdir", "wsp", userWID.toString())
        userTopPath.toFile().mkdirs()
        makeTestFile(userTopPath.toString(), fileSize = 1024)

        val info = getQuotaInfo(db, userWID).getOrThrow()
        val rs = db.query("SELECT usage,quota FROM quotas WHERE wid=?", userWID).getOrThrow()
        assert(rs.next())
        assertEquals(info.first, rs.getLong("usage"))
        assertEquals(info.second, rs.getLong("quota"))

        makeTestFile(userTopPath.toString(), fileSize = 1024)

        // This should be different from the actual value -- we are expected
        // to notify the system of any changes while the server is running
        assertEquals(info.first, getQuotaInfo(db, userWID).getOrThrow().first)

        resetQuotaUsage(db)?.let { throw it }
        assertEquals(2048, getQuotaInfo(db, userWID).getOrThrow().first)
        db.disconnect()
    }

    @Test
    fun modifyQuotaUsageTest() {
        val setupData = setupTest("dbcmds.modifyQuotaUsage")
        val db = DBConn()
        setupUser(db)

        val userWID = RandomID.fromString(USER_PROFILE_DATA["wid"])!!
        val userTopPath = Paths.get(setupData.testPath, "topdir", "wsp", userWID.toString())
        userTopPath.toFile().mkdirs()
        makeTestFile(userTopPath.toString(), fileSize = 3000)

        // Usage hasn't been loaded, so the value should be ignored here.
        assertEquals(3000, modifyQuotaUsage(db, userWID, 1000).getOrThrow())
        makeTestFile(userTopPath.toString(), fileSize = 1000)
        assertEquals(4000, modifyQuotaUsage(db, userWID, 1000).getOrThrow())

        assertEquals(4000, getQuotaInfo(db, userWID).getOrThrow().first)
        db.disconnect()
    }

    @Test
    fun setQuotaTest() {
        val setupData = setupTest("dbcmds.setQuota")
        val db = DBConn()
        setupUser(db)

        val userWID = RandomID.fromString(USER_PROFILE_DATA["wid"])!!
        val userTopPath = Paths.get(setupData.testPath, "topdir", "wsp", userWID.toString())
        userTopPath.toFile().mkdirs()
        makeTestFile(userTopPath.toString(), fileSize = 0x100_000)

        // Set the quota for 2MB
        setQuota(db, userWID, 0x200_000)?.let { throw it }

        val rs = db.query("SELECT usage,quota FROM quotas WHERE wid=?", userWID).getOrThrow()
        assert(rs.next())
        assertEquals(0x100_000, rs.getLong("usage"))
        assertEquals(0x200_000, rs.getLong("quota"))
        db.disconnect()
    }

    @Test
    fun setQuotaUsageTest() {
        val setupData = setupTest("dbcmds.setQuotaUsage")
        val db = DBConn()
        setupUser(db)

        val userWID = RandomID.fromString(USER_PROFILE_DATA["wid"])!!
        val userTopPath = Paths.get(setupData.testPath, "topdir", "wsp", userWID.toString())
        userTopPath.toFile().mkdirs()

        var info = getQuotaInfo(db, userWID).getOrThrow()
        assertEquals(0, info.first)
        makeTestFile(userTopPath.toString(), fileSize = 2000)
        info = getQuotaInfo(db, userWID).getOrThrow()
        assertEquals(0, info.first)

        setQuotaUsage(db, userWID, 2000L)?.let { throw it }
        info = getQuotaInfo(db, userWID).getOrThrow()
        assertEquals(2000, info.first)
        db.disconnect()
    }
}