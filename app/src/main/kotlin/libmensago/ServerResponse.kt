package libmensago

import keznacl.toFailure
import keznacl.toSuccess
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import mensagod.logDebug
import java.io.InputStream
import java.net.Socket

@Serializable
class ServerResponse(
    @Required @SerialName("Code") var code: Int = 0,
    @Required @SerialName("Status") var status: String = "",
    @SerialName("Info") var info: String = "",
    @SerialName("Data") var data: MutableMap<String, String> = mutableMapOf()
) {

    /**
     * Functional method which adds the requested data to the message.
     */
    fun attach(name: String, value: Any): ServerResponse {
        data[name] = value.toString()
        return this
    }

    /**
     * Checks attached data for the requested fields in the pair list. The bool parameter is
     * for specifying if the field is required. Returns true if all required fields are present.
     */
    fun checkFields(schema: List<Pair<String, Boolean>>): Boolean {
        return schema.none { !data.containsKey(it.first) && it.second }
    }

    /**
     * Converts the ServerResponse to JSON and sends it out a connection as a message.
     *
     * @throws kotlinx.serialization.SerializationException encoding-specific errors
     * @throws IllegalArgumentException if the encoded input does not comply format's specification
     * @throws java.io.IOException if there was a network error
     */
    fun send(conn: Socket): Throwable? {
        return runCatching {
            val jsonStr = Json.encodeToString(this)
            writeMessage(conn.getOutputStream(), jsonStr.encodeToByteArray())
            null
        }.getOrElse { it }
    }

    /**
     * Works just like send(), except it is intended to be used in instances where nothing useful
     * can be done for any exceptions thrown. Instead, an error is logged for any exception
     * conditions. It returns true upon success and false upon error.
     */
    fun sendCatching(conn: Socket, message: String): Boolean {
        runCatching {
            val jsonStr = Json.encodeToString(this)
            writeMessage(conn.getOutputStream(), jsonStr.encodeToByteArray())
        }.getOrElse {
            logDebug("$message: $it")
            return false
        }
        return true
    }

    /** Returns a CmdStatus object based on the contents of the server response */
    fun toStatus(): CmdStatus {
        return CmdStatus(code, status, info)
    }

    override fun toString(): String {
        return if (info.isNotEmpty()) "ServerResponse -> $code: $status ($info)"
        else "ServerResponse -> $code: $status"
    }

    companion object {
        /** Reads a ServerResponse from a connection */
        fun receive(conn: InputStream): Result<ServerResponse> {

            val jsonMsg = readStringMessage(conn).getOrElse { return it.toFailure() }
            val response = runCatching {
                Json.decodeFromString<ServerResponse>(jsonMsg)
            }.getOrElse { return it.toFailure() }

            return response.toSuccess()
        }
    }
}
