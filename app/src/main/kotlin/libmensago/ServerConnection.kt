package libmensago

import keznacl.toFailure
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

@Serializable
data class ServerGreeting(
    @SerialName("Name") val name: String,
    @SerialName("Version") val version: String,
    @SerialName("Code") val code: Int,
    @SerialName("Status") val status: String,
    @SerialName("Date") val date: String
)

/**
 * The MConn trait is for any type which implements the methods needed for connecting to a Mensago
 * server. It exists mostly an abstraction for mocking a server connection.
 */
interface MConn {
    /** Connects to a Mensago server */
    fun connect(address: InetAddress, port: Int): Throwable?

    /** Gracefully disconnects from a Mensago server */
    fun disconnect(): Throwable?

    /** Returns true if connected */
    fun isConnected(): Boolean

    /** Waits for a ServerResponse from a connected Mensago server */
    fun receive(): Result<ServerResponse>

    /** Sends a ClientRequest to a server */
    fun send(msg: ClientRequest): Throwable?

    /** A low-level data read from the port */
    fun read(data: ByteArray): Result<Int>

    /** A low-level data dump to the port */
    fun write(data: ByteArray): Throwable?
}

/**
 * The ServerConnection type is a low-level connection to a Mensago server that operates over a TCP
 * stream.
 */
class ServerConnection : MConn {
    private var socket: Socket? = null

    override fun connect(address: InetAddress, port: Int): Throwable? {
        val addr = runCatching {
            InetSocketAddress(address, port)
        }.getOrElse { return it }

        val tempSocket = Socket()
        tempSocket.connect(addr, 1800000)

        // Absorb the hello string for now
        val inStream = tempSocket.getInputStream()
        val hello = BufferedReader(InputStreamReader(inStream)).readLine()

        val greeting = runCatching {
            Json.decodeFromString<ServerGreeting>(hello)
        }.getOrElse {
            return ServerException("Bad greeting")
        }

        if (greeting.code != 200)
            return ProtocolException(
                CmdStatus(
                    greeting.code, greeting.status,
                    "${greeting.name} / ${greeting.date} / ${greeting.version}"
                )
            )

        socket = tempSocket
        return null
    }

    override fun disconnect(): Throwable? {
        if (socket != null) {
            if (!socket!!.isClosed)
                send(ClientRequest("QUIT"))?.let { return it }
            runCatching { socket!!.close() }.getOrElse { return it }
            socket = null
        }
        return null
    }

    override fun isConnected(): Boolean {
        return if (socket != null) {
            !socket!!.isClosed
        } else false
    }

    override fun receive(): Result<ServerResponse> {
        if (socket == null) return Result.failure(NotConnectedException())

        val inStream = runCatching { socket!!.getInputStream() }
            .getOrElse { return it.toFailure() }
        return ServerResponse.receive(inStream)
    }

    override fun send(msg: ClientRequest): Throwable? {
        if (socket == null) return NotConnectedException()

        val outStream = runCatching { socket!!.getOutputStream() }
            .getOrElse { return it }

        return msg.send(outStream)
    }

    override fun read(data: ByteArray): Result<Int> {
        if (socket == null) return Result.failure(NotConnectedException())

        return runCatching {
            val inStream = socket!!.getInputStream()
            Result.success(inStream.read(data))
        }.getOrElse { it.toFailure() }
    }

    override fun write(data: ByteArray): Throwable? {
        if (socket == null) return NotConnectedException()

        return runCatching {
            val outStream = socket!!.getOutputStream()
            outStream.write(data)
            null
        }.getOrElse { it }
    }
}
