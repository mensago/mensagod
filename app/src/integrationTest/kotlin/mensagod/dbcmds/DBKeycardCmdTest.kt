package mensagod.dbcmds

import libkeycard.MAddress
import libkeycard.RandomID
import mensagod.DBConn
import mensagod.ServerConfig
import mensagod.initServer
import mensagod.setupTest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class DBKeycardCmdTest {
    @Test
    fun resolveWIDAddress() {
        val config = ServerConfig.load()
        setupTest(config)
        DBConn.initialize(config)
        val db = DBConn().connect()
        val setupData = initServer(db.getConnection()!!)

        // Using support instead of admin because we don't have to go through the registration
        // process for admin this way.
        assertNotNull(resolveAddress(MAddress.fromString("support/example.com")!!))

        // admin hasn't been registered yet, so this one should be null
        assertNull(resolveAddress(MAddress.fromString("admin/example.com")!!))

        val supportWID = RandomID.fromString(setupData["support_wid"])!!
        assertEquals("example.com", resolveWID(db, supportWID)?.domain.toString())
        assertNull(resolveWID(db,
            RandomID.fromString("00000000-0000-0000-0000-000000000000")!!))
    }
}