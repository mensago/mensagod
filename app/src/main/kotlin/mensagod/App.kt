package mensagod

import keznacl.BadValueException
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import libkeycard.Domain
import mensagod.commands.ClientRequest
import mensagod.commands.processCommand
import java.io.IOException
import java.net.ServerSocket
import java.net.Socket
import java.nio.file.Paths
import java.time.Instant
import java.time.format.DateTimeFormatter
import kotlin.system.exitProcess

/**
 * The ServerGreeting class is used for the initial greeting a server provides when a client
 * connects.
 */
@Serializable
data class ServerGreeting(@SerialName("Name") val name: String,
                          @SerialName("Version") val version: String,
                          @SerialName("Code") val code: Int,
                          @SerialName("Status") val status: String,
                          @SerialName("Date") val date: String)

/**
 * The Server class encapsulates the the top level of abstraction for the server and houses the
 * main run loop.
 */
class Server private constructor(val config: ServerConfig) {

    private var clientPool = WorkerPool()

    /** Starts the server execution loop */
    fun run() {

        // Main listener loop

        val listener = try { ServerSocket(config.getInteger("network.port")!!) }
        catch (e: IOException) {
            println("Unable to open network connection:\n$e")
            exitProcess(-1)
        }
        println("Listening on port ${config.getInteger("network.port")}")

        while (true) {
            val conn = try { listener.accept() }
            catch (e: IOException) {
                logWarn("Failure to accept connection: $e")
                continue
            }

            val id = clientPool.add()
            if (id == null) {
                sendGreeting(conn, 303, "SERVER UNAVAILABLE")
                continue
            }

            Thread.ofVirtual().start { connectionWorker(conn) }
        }

        // TODO: implement graceful server shutdown
        // close listener here
    }

    companion object {

        /** Performs setup needed for the server to run. */
        fun initialize(): Result<Server> {
            val config = ServerConfig.load()
            config.validate()?.let { return Result.failure(BadValueException(it)) }

            val logLocation = Paths.get(config.getString("global.log_dir")!!, "mensagod.log")
            initLogging(logLocation, false)
            DBConn.initialize(config)

            val out = Server(config)
            out.clientPool.capacity = config.getInteger("performance.max_client_threads")!!

            gServerDomain = Domain.fromString(config.getString("global.domain"))!!

            return Result.success(out)
        }
    }
}

/**
 * sendGreeting sends to a client the server greeting. It returns false if an error occurred while
 * trying to send the greeting.
 */
fun sendGreeting(conn: Socket, code: Int, status: String): Boolean {
    val now = Instant.now().let { it.minusNanos(it.nano.toLong()) }
    val greeting = ServerGreeting("Mensago", "0.1", code, status,
        DateTimeFormatter.ISO_INSTANT.format(now))
    val greetingJSON = try { Json.encodeToString(greeting) + "\r\n" }
    catch (e: SerializationException) {
        logError("Unable to serialize unavailability greeting")
        return false
    }

    val ostream = try { conn.getOutputStream() }
    catch (e: IOException) {
        logError("Unable to open client socket for writing")
        return false
    }

    try { ostream.write(greetingJSON.encodeToByteArray()) }
    catch (e: Exception) {
        // At this point, it doesn't really matter if we fail out anyway :(
        return false
    }
    return true
}

/**
 * connectionWorker() is the service function used by the server's coroutines to handle client
 * connections.
 */
fun connectionWorker(conn: Socket) {
    val state = ClientSession(conn)
    if (!sendGreeting(conn, 200, "OK")) {
        conn.close()
        return
    }

    val istream = try { conn.getInputStream() }
    catch (e: IOException) {
        logError("Failed to open input stream for client: $e")
        conn.close()
        return
    }

    var networkErrorCount = 0
    while(true) {
        val req = try { ClientRequest.receive(istream) }
        catch (e: SerializationException) {
            // If there was a serialization problem, that means the client is having problems. For
            // now, we'll just ignore this and move on unless it becomes a problem.
            continue
        }
        catch (e: IllegalArgumentException) {
            // Don't know why we'd get this error, so for now, just ignore and continue
            continue
        }
        catch (e: IOException) {
            networkErrorCount++
            if (networkErrorCount >= gMaxNetworkErrors) break
            continue
        }
        networkErrorCount = 0
        state.message = req

        if (req.action.uppercase() == "QUIT") break

        try { processCommand(state) }
        catch (e: IOException) { networkErrorCount++ }

        if (state.isTerminating) break
    }

    conn.close()
}

fun main() {
    val server = Server.initialize().getOrElse {
        try {
            logError("Initialization failure: $it")
            println("Initialization failure. Please check the log for more details.")
        }
        catch (e: Exception) {
            println("Initialization failure: $it")
        }
        return
    }
    server.run()
}
