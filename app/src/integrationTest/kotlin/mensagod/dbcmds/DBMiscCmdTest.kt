package mensagod.dbcmds

import mensagod.DBConn
import mensagod.ServerConfig
import mensagod.initServer
import mensagod.setupTest
import org.junit.jupiter.api.Test

class DBMiscCmdTest {
    @Test
    fun keypairTest() {
        val config = ServerConfig.load()
        setupTest(config)
        DBConn.initialize(config)
        val dbConn = DBConn().connect().getConnection()!!
        initServer(dbConn)

        // These methods will return the proper data or throw, so we don't have to do anything to
        // test them except call them. :)
        getEncryptionPair()
        getPrimarySigningPair()
    }
}