package mensagod.handlers

import libmensago.ClientRequest
import libmensago.ServerResponse
import mensagod.DBConn
import mensagod.ServerConfig
import mensagod.SessionState
import mensagod.resetDB
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import testsupport.initDB
import java.net.InetAddress
import java.net.Socket

class MiscCmdTest {

    @Test
    fun getWIDTest() {
        val config = ServerConfig.load().getOrThrow()
        resetDB(config).getOrThrow()
        DBConn.initialize(config)?.let { throw it }
        val serverData = initDB(DBConn().connect().getOrThrow().getConnection()!!)

        val state = SessionState(
            message = ClientRequest("GETWID", mutableMapOf("User-ID" to "support"))
        )

        CommandTest("getWID", state, ::commandGetWID) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            assertEquals(200, response.code)
            assertEquals(serverData["support_wid"]!!, response.data["Workspace-ID"])
        }.run()
    }
}
