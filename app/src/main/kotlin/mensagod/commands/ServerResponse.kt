package mensagod.commands

import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.InputStream
import java.net.Socket

@Serializable
class ServerResponse(@Required @SerialName("Code") var code: Int = 0,
                     @Required @SerialName("Status") var status: String = "",
                     @SerialName("Info") var info: String = "",
                     @SerialName("Data") var data: MutableMap<String, String> = mutableMapOf()) {

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
    fun send(conn: Socket) {
        val jsonStr = Json.encodeToString(this)
        writeMessage(conn.getOutputStream(), jsonStr.encodeToByteArray())
    }

    /** Returns a CmdStatus object based on the contents of the server response */
    fun toStatus(): CmdStatus { return CmdStatus(code, status, info) }

    companion object {
        /** Reads a ServerResponse from a connection */
        fun receive(conn: InputStream): Result<ServerResponse> {

            val jsonMsg = readStringMessage(conn)
            val response = try {
                Json.decodeFromString<ServerResponse>(jsonMsg)
            } catch (e: Exception) { return Result.failure(e) }

            return Result.success(response)
        }

        /**
         * Static method which sends a 300 INTERNAL SERVER ERROR message to the client. It
         * suppresses network errors because we're already in an error state.
         *
         * @throws kotlinx.serialization.SerializationException encoding-specific errors
         * @throws IllegalArgumentException if the encoded input does not comply format's specification
         */
        fun sendInternalError(info: String, conn: Socket) {
            try { ServerResponse(300, "INTERNAL SERVER ERROR", info).send(conn) }
            catch (e: java.io.IOException) { /* Suppress network errors */ }
        }
    }
}

@Serializable
class CmdStatus(var code: Int, var description: String, var info: String) {
    override fun toString(): String {
        return if (info.isEmpty()) "$code: $description"
        else "$code: $description ($info)"
    }
}