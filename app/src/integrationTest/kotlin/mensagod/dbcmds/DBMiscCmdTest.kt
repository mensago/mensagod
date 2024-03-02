package mensagod.dbcmds

import mensagod.DBConn
import mensagod.ServerConfig
import mensagod.resetDB
import org.junit.jupiter.api.Test
import testsupport.initDB

class DBMiscCmdTest {

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