package mensagod

import libmensago.ServerResponse
import java.net.Socket

object QuickResponse {

    /**
     * Static method which sends a 300 INTERNAL SERVER ERROR message to the client. It
     * suppresses network errors because we're already in an error state.
     *
     * @throws kotlinx.serialization.SerializationException encoding-specific errors
     * @throws IllegalArgumentException if the encoded input does not comply format's specification
     */
    fun sendInternalError(info: String, conn: Socket) {
        ServerResponse(300, "INTERNAL SERVER ERROR", info)
            .sendCatching(conn, "Error sending quick Internet Error")
    }
}
