package mensagod.commands

import mensagod.ClientSession
import mensagod.SessionState
import java.net.ServerSocket

class CommandTest(private val state: SessionState,
                  private val command: (ClientSession) -> Unit,
                  private val clientCode: (port: Int)-> Unit) {

    private val srvSocket = ServerSocket(0)

    fun run() {
        val serverThread = Thread.ofVirtual().start { serverWorker(srvSocket, state) }
        val clientThread = Thread.ofVirtual().start {
            Thread.sleep(500)
            clientCode(srvSocket.localPort)
        }
        serverThread.join()
        clientThread.join()
    }

    private fun serverWorker(listener: ServerSocket, state: SessionState) {
        val socket = listener.accept()
        val serverState = ClientSession(socket).also {
            it.loginState = state.loginState
            it.isTerminating = state.isTerminating
            it.wid = state.wid
            it.devid = state.devid
            it.message = state.message
        }
        command(serverState)
    }
}
