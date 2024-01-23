package mensagod.commands

import mensagod.ClientSession
import mensagod.SessionState
import java.net.ServerSocket
import kotlin.system.exitProcess

class CommandTest(private val testName: String,
                  private val state: SessionState,
                  private val command: (ClientSession) -> Unit,
                  private val clientCode: (port: Int)-> Unit) {
    private val srvSocket = ServerSocket(0)

    fun run() {
        try {
            val serverThread = Thread.ofVirtual().let {
                it.name("$testName: Server")
                it.start { serverWorker(srvSocket, state) }
            }
            Thread.sleep(100)

            val clientThread = Thread.ofVirtual().let{
                it.name("$testName: Client")
                it.start { clientCode(srvSocket.localPort) }
            }
            serverThread.join()
            clientThread.join()
        } catch (e: Exception) { exitProcess(-1) }
    }

    private fun serverWorker(listener: ServerSocket, state: SessionState) {
        try {
            val socket = listener.accept()
            val serverState = ClientSession(socket).also {
                it.loginState = state.loginState
                it.isTerminating = state.isTerminating
                it.wid = state.wid
                it.devid = state.devid
                it.message = state.message
            }
            command(serverState)
        } catch (e: Exception) { exitProcess(-1) }
    }
}
