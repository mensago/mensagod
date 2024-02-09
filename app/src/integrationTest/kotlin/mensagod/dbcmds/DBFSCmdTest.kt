package mensagod.dbcmds

import libkeycard.RandomID
import mensagod.*
import org.junit.jupiter.api.Test
import java.nio.file.Paths

class DBFSCmdTest {

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
    }
    // TODO: Implement quota tests
}