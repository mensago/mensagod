package mensagod

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import libmensago.ServerResponse
import libmensago.writeMessage
import java.net.Socket

object QuickResponse {

    /**
     * Static method which sends a 400 BAD REQUEST message to the client. It
     * suppresses network errors because we're already in an error state.
     *
     * @throws kotlinx.serialization.SerializationException encoding-specific errors
     * @throws IllegalArgumentException if the encoded input does not comply format's specification
     */
    fun sendBadRequest(info: String, conn: Socket) {
        try { ServerResponse(400, "BAD REQUEST", info).send(conn) }
        catch (e: java.io.IOException) { /* Suppress network errors */ }
    }

    /**
     * Static method which sends a 403 FORBIDDEN message to the client. It
     * suppresses network errors because we're already in an error state.
     *
     * @throws kotlinx.serialization.SerializationException encoding-specific errors
     * @throws IllegalArgumentException if the encoded input does not comply format's specification
     */
    fun sendForbidden(info: String, conn: Socket) {
        try { ServerResponse(403, "FORBIDDEN", info).send(conn) }
        catch (e: java.io.IOException) { /* Suppress network errors */ }
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

    /**
     * Static method which sends a 300 INTERNAL SERVER ERROR message to the client. It
     * suppresses network errors because we're already in an error state.
     *
     * @throws kotlinx.serialization.SerializationException encoding-specific errors
     * @throws IllegalArgumentException if the encoded input does not comply format's specification
     */
    fun sendNotFound(info: String, conn: Socket) {
        try { ServerResponse(404, "RESOURCE NOT FOUND", info).send(conn) }
        catch (e: java.io.IOException) { /* Suppress network errors */ }
    }
}

/**
 * Works just like send(), except it is intended to be used in instances where nothing useful
 * can be done for any exceptions thrown. Instead, an error is logged for any exception
 * conditions. It returns true upon success and false upon error.
 */
fun ServerResponse.sendCatching(conn: Socket, message: String): Boolean {
    try {
        val jsonStr = Json.encodeToString(this)
        writeMessage(conn.getOutputStream(), jsonStr.encodeToByteArray())
    }
    catch (e: Exception) {
        logDebug("$message: $e")
        return false
    }
    return true
}

