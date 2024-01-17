package mensagod.dbcmds

import libkeycard.MAddress
import mensagod.DBConn
import mensagod.ServerConfig
import mensagod.initServer
import mensagod.setupTest
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class DBKeycardCmdTest {
    @Test
    fun resolveAddress() {
        val config = ServerConfig.load()
        setupTest(config)
        DBConn.initialize(config)
        val dbConn = DBConn().connect().getConnection()!!
        initServer(dbConn)

        // Using support instead of admin because we don't have to go through the registration
        // process for admin this way.
        assertNotNull(
            resolveAddress(
            MAddress.fromString("support/example.com")!!)
        )

        // admin hasn't been registered yet, so this one should be null
        assertNull(
            resolveAddress(
            MAddress.fromString("admin/example.com")!!)
        )
    }
}