package mensagod.handlers

import mensagod.ClientSession
import mensagod.SessionState
import mensagod.delivery.shutdownDeliveryThreads
import java.lang.Thread.sleep
import java.net.ServerSocket

class CommandTest(
    private val testName: String,
    private val state: SessionState,
    private val command: (ClientSession) -> Unit,
    private val clientCode: (port: Int) -> Unit
) {
    private val srvSocket = ServerSocket(0)

    fun run() {
        var serverException: Throwable? = null
        var clientException: Throwable? = null

        val serverThread = Thread.ofVirtual().let {
            it.name("$testName: Server")
            it.uncaughtExceptionHandler { _, throwable -> serverException = throwable }
            it.start { serverWorker(srvSocket, state) }
        }
        // This little sleep call ensures that delivery threads have enough time to work and that
        // client threads are waiting on the server thread
        sleep(100)

        val clientThread = Thread.ofVirtual().let {
            it.name("$testName: Client")
            it.uncaughtExceptionHandler { _, throwable -> clientException = throwable }
            it.start { clientCode(srvSocket.localPort) }
        }

        serverThread.join()
        serverException?.let { throw it }
        clientThread.join()
        clientException?.let { throw it }
    }

    private fun serverWorker(listener: ServerSocket, state: SessionState) {
        val socket = listener.accept()
        val serverState = ClientSession(socket).also {
            it.loginState = state.loginState
            it.isTerminating = state.isTerminating
            it.wid = state.wid
            it.devid = state.devid
            it.message = state.message
            it.currentPath = state.currentPath
        }
        command(serverState)
        sleep(100)
        shutdownDeliveryThreads()
    }
}
