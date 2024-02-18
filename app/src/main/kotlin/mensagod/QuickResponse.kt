package mensagod

import libmensago.ServerResponse
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
}