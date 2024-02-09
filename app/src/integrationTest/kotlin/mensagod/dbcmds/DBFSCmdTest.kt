package mensagod.dbcmds

import libkeycard.RandomID
import mensagod.*
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.nio.file.Paths

class DBFSCmdTest {

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
    }

    // TODO: Implement quota tests
}