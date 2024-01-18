package mensagod.dbcmds

import libkeycard.RandomID
import libkeycard.UserID
import mensagod.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class DBLoginCmdTest {
    @Test
    fun preregWorkspaceTest() {
        val config = ServerConfig.load()
        setupTest(config)
        DBConn.initialize(config)
        val dbConn = DBConn().connect().getConnection()!!
        val serverData = initServer(dbConn)

        val newWID = RandomID.fromString("94fd481f-6b1c-459b-ada7-5f32b3a1bbf3")!!
        val newUID = UserID.fromString("csimons")
        val supportWID = RandomID.fromString(serverData["support_wid"])!!
        val supportUID = UserID.fromString("support")
        val domain = gServerDomain
        assertThrows<ResourceExistsException> {
            preregWorkspace(supportWID, null, domain, "foobar")
        }
        assertThrows<ResourceExistsException> {
            preregWorkspace(supportWID, supportUID, domain, "foobar")
        }

        // TODO: Finish preregWorkspaceTest
    }
}
