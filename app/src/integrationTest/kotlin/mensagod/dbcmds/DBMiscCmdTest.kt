package mensagod.dbcmds

import mensagod.DBConn
import mensagod.ServerConfig
import mensagod.initDB
import mensagod.resetDB
import org.junit.jupiter.api.Test

class DBMiscCmdTest {
    @Test
    fun keypairTest() {
        val config = ServerConfig.load()
        resetDB(config)
        DBConn.initialize(config)
        val dbConn = DBConn().connect().getConnection()!!
        initDB(dbConn)

        // These methods will return the proper data or throw, so we don't have to do anything to
        // test them except call them. :)
        getEncryptionPair()
        getPrimarySigningPair()
    }
}