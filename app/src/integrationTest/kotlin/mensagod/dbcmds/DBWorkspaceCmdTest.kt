package mensagod.dbcmds

import libkeycard.RandomID
import mensagod.DBConn
import mensagod.ServerConfig
import mensagod.initServer
import mensagod.setupTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class DBWorkspaceCmdTest {

    @Test
    fun checkWorkspaceTest() {
        val config = ServerConfig.load()
        setupTest(config)
        DBConn.initialize(config)
        val dbConn = DBConn().connect().getConnection()!!
        val serverData = initServer(dbConn)

        assertEquals(WorkspaceStatus.Active,
            checkWorkspace(RandomID.fromString(serverData["support_wid"])!!))
        assertNull(checkWorkspace(
            RandomID.fromString("00000000-0000-0000-0000-000000000000")!!))
    }
}