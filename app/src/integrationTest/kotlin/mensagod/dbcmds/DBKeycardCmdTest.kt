package mensagod.dbcmds

import libkeycard.MAddress
import libkeycard.RandomID
import mensagod.DBConn
import mensagod.ServerConfig
import mensagod.initDB
import mensagod.resetDB
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class DBKeycardCmdTest {

    // getEntries() is tested by the test for commandAddEntry. It suffers from a chicken-and-egg
    // problem and would require a ton of code to test independently.

    @Test
    fun resolveWIDAddressTest() {
        val config = ServerConfig.load()
        resetDB(config)
        DBConn.initialize(config)
        val db = DBConn().connect()
        val setupData = initDB(db.getConnection()!!)

        // Using support instead of admin because we don't have to go through the registration
        // process for admin this way.
        assertNotNull(resolveAddress(db, MAddress.fromString("support/example.com")!!))

        // admin hasn't been registered yet, so this one should be null
        assertNull(resolveAddress(db, MAddress.fromString("admin/example.com")!!))

        val supportWID = RandomID.fromString(setupData["support_wid"])!!
        assertEquals("example.com", resolveWID(db, supportWID)?.domain.toString())
        assertNull(resolveWID(db,
            RandomID.fromString("00000000-0000-0000-0000-000000000000")!!))
    }
}