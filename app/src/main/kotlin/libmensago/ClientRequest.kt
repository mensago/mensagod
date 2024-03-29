package libmensago

import keznacl.toFailure
import keznacl.toSuccess
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.InputStream
import java.io.OutputStream

/**
 * The ClientRequest class handles sending and receiving of Mensago client requests.
 */
@Serializable
class ClientRequest(
    @SerialName("Action") var action: String,
    @SerialName("Data") var data: MutableMap<String, String> = mutableMapOf()
) {

    /**
     * Functional method which adds the requested data to the message.
     */
    fun attach(name: String, value: Any): ClientRequest {
        data[name] = value.toString()
        return this
    }

    /**
     * Convenience function which returns true if the request has the specified field.
     */
    fun hasField(fieldname: String): Boolean {
        return data.containsKey(fieldname)
    }

    /**
     * Converts the ClientRequest to JSON and sends it out a connection.
     *
     * @throws kotlinx.serialization.SerializationException encoding-specific errors
     * @throws IllegalArgumentException if the encoded input does not comply format's specification
     */
    fun send(conn: OutputStream): Throwable? {
        return runCatching {
            val jsonStr = Json.encodeToString(this)
            writeMessage(conn, jsonStr.encodeToByteArray())
            null
        }.getOrElse { it }
    }

    /**
     * Performs schema validation for the request, ensuring that the request contains all of the
     * fields passed to the method. Success is indicated by this method returning null. If a string
     * is returned by the method, it is the first missing field encountered.
     */
    fun validate(fields: Set<String>): String? {
        fields.forEach { if (!data.containsKey(it)) return it }
        return null
    }

    companion object {
        /**
         * Reads a ClientRequest from a connection as a message containing raw JSON and converts
         * it into a data structure.
         *
         * @throws kotlinx.serialization.SerializationException encoding-specific errors
         * @throws IllegalArgumentException if the encoded input does not comply format's specification
         * @throws java.io.IOException if there was a network error
         */
        fun receive(conn: InputStream): Result<ClientRequest> {
            val jsonMsg = readStringMessage(conn).getOrElse {
                return java.io.IOException("SysMessage session error").toFailure()
            }
            val out = runCatching {
                Json.decodeFromString<ClientRequest>(jsonMsg)
            }.getOrElse { return it.toFailure() }
            return out.toSuccess()
        }
    }
}
