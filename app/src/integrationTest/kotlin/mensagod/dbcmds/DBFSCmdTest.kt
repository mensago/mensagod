package mensagod.dbcmds

import mensagod.DBConn
import mensagod.setupTest
import mensagod.setupUser
import org.junit.jupiter.api.Test

class DBFSCmdTest {

    @Test
    fun setQuotaTest() {
        val setupData = setupTest("dbcmds.setQuota")
        val db = DBConn()
        setupUser(db)

        // TODO: Implement setQuotaTest()
    }
}