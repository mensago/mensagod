package mensagod.commands

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import mensagod.ClientSession
import org.junit.jupiter.api.Test
import java.net.ServerSocket

class CommandTest(private val request: ClientRequest,
                  private val command: (ClientSession) -> Unit,
                  private val clientCode: ()-> Unit) {

    private val scope = CoroutineScope(Dispatchers.IO)
    private val srvSocket = ServerSocket(0)

    fun run() {
        scope.launch { serverWorker(srvSocket, request) }
        scope.launch {
            delay(100)
            clientWorker(srvSocket.localPort)
        }
    }

    private fun serverWorker(listener: ServerSocket, request: ClientRequest) {
        val socket = listener.accept()
        val state = ClientSession(socket)
        command(state)
    }

    private fun clientWorker(serverPort: Int) {

    }
}

class MiscCmdTest {

    @Test
    fun getWIDTest() {
//        CommandTest(ClientRequest("GETWID", mutableMapOf("User-ID" to "support")),
//            commandGetWID,
//            {}
//        ).run()

        // TODO: Implement getWIDTest() and all support code to go with it
    }
}
