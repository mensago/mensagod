package mensagod.commands

import libkeycard.RandomID
import mensagod.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.net.InetAddress
import java.net.Socket

class RegCmdTest {
    @Test
    fun preregTest() {
        val config = ServerConfig.load()
        resetDB(config)
        DBConn.initialize(config)
        val db = DBConn().connect()
        initDB(db.getConnection()!!)
        setupAdmin(db)

        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!

        // Test Case #1: Supply no data. Expect WID, Domain, and reg code
        CommandTest(SessionState(ClientRequest("PREREG", mutableMapOf()), adminWID,
                LoginState.LoggedIn), ::commandPreregister) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            assertEquals(200, response.code)
            assertNull(response.data["User-ID"])
            assertEquals(gServerDomain.toString(), response.data["Domain"])
            assertNotNull(RandomID.fromString(response.data["Workspace-ID"]))
            assertEquals(config.getInteger("security.diceware_wordcount"),
                response.data["Reg-Code"]?.split(" ")?.size)

            // TODO: Finish preregTest. Depends on admin registration support code
        }.run()
    }
}