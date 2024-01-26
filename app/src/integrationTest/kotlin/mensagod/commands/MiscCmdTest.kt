package mensagod.commands

import mensagod.*
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.net.InetAddress
import java.net.Socket

class MiscCmdTest {

    @Test
    fun getWIDTest() {
        val config = ServerConfig.load()
        resetDB(config)
        DBConn.initialize(config)
        val serverData = initDB(DBConn().connect().getConnection()!!)

        val state = SessionState(
            message = ClientRequest("GETWID", mutableMapOf("User-ID" to "support")))

        CommandTest("getWID", state, ::commandGetWID) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            assertEquals(200, response.code)
            assertEquals(serverData["support_wid"]!!, response.data["Workspace-ID"])
        }.run()
    }
}
