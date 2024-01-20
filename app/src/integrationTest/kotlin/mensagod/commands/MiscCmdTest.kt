package mensagod.commands

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import mensagod.*
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket

class CommandTest(private val request: ClientRequest,
                  private val command: (ClientSession) -> Unit,
                  private val clientCode: (port: Int)-> Unit) {

    private val scope = CoroutineScope(Dispatchers.IO)
    private val srvSocket = ServerSocket(0)

    fun run() {
        Thread.ofVirtual().start { serverWorker(srvSocket, request) }
        Thread.ofVirtual().start {
            Thread.sleep(1000)
            clientCode(srvSocket.localPort)
        }
    }

    private fun serverWorker(listener: ServerSocket, request: ClientRequest) {
        val socket = listener.accept()
        val state = ClientSession(socket)
        state.message = request
        command(state)
    }
}

class MiscCmdTest {

    @Test
    fun getWIDTest() {
        val config = ServerConfig.load()
        setupTest(config)
        DBConn.initialize(config)
        initServer(DBConn().connect().getConnection()!!)

        CommandTest(ClientRequest("GETWID", mutableMapOf("User-ID" to "support")),
            ::commandGetWID) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            assertEquals(200, response.code)
        }.run()
    }

    // TODO: Implement other command tests
}
