package mensagod.commands

import keznacl.EmptyDataException
import mensagod.BadFrameException
import mensagod.BadSessionException
import mensagod.FrameTypeException
import mensagod.SizeException
import java.io.InputStream
import java.io.OutputStream

const val MAX_MSG_SIZE: Int = 65532

/**
 * DataFrame is a structure for the lowest layer of network interaction. It represents a segment of
 * data. Depending on the type code for the instance, it may indicate that the data payload is
 * complete -- the SingleFrame type -- or it may be part of a larger set. In all cases a DataFrame
 * is required to be equal to or smaller than the permitted buffer size of 64KiB.
 */
class DataFrame {

    private var index = 0
    private val buffer = ByteArray(MAX_MSG_SIZE)

    var type: FrameType = FrameType.InvalidFrame

    val size: Int
        get() { return index }

    val payload: ByteArray
        get() { return buffer.sliceArray(IntRange(0, index - 1)) }

    /**
     * Returns the size of a multipart frame.
     *
     * @throws BadFrameException if the frame header is invalid or if the data is not an integer
     * @throws FrameTypeException if called on a frame that is not MultipartFrameStart
     */
    fun getMultipartSize(): Int {
        if (size < 1) throw BadFrameException("Invalid frame header")
        if (type != FrameType.MultipartFrameStart) throw FrameTypeException()

        return try { payload.decodeToString().toInt() }
        catch (e: NumberFormatException) { throw BadFrameException("Invalid start frame payload") }
    }

    /**
     * The lowest-level code for reading data from a socket, short of reading the socket directly.
     *
     * @throws BadFrameException when the frame header is invalid
     * @throws SizeException if the amount of data read does not match the size specified in the frame header
     * @throws java.io.IOException if there was a network error
     */
    fun read(conn: InputStream) {
        // Invalidate internal data in case we error out
        index = 0

        val header = ByteArray(3)
        var bytesRead = conn.read(header)
        if (bytesRead < 3) throw BadFrameException("Invalid frame header")

        type = FrameType.fromByte(header[0])
        if (type == FrameType.InvalidFrame) throw BadFrameException("Bad frame type $type")

        // The size bytes are in network order (MSB), so this makes dealing with CPU architecture
        // much less of a headache regardless of what archictecture this is compiled for.

        // Once again, however, Java's complete lack of unsigned types come back to cause trouble.
        // Again. Which leads to more hoops to jump through.
        val payloadMSB = header[1].toUByte().toInt().shl(8)
        val payloadLSB = header[2].toUByte().toInt()
        val payloadSize = payloadMSB.or(payloadLSB)

        bytesRead = conn.read(buffer, 0, payloadSize)
        if (bytesRead != payloadSize) throw SizeException()

        index = bytesRead
    }
}

/**
 * The lowest-level code for writing data over a socket. It will accept up to 65532 bytes of data
 * as a message payload.
 * @throws SizeException if the payload is larger than the maximum message size
 * @throws java.io.IOException if there was a problem with the socket itself.
 */
fun writeFrame(conn: OutputStream, frameType: FrameType, payload: ByteArray) {
    if (payload.size > MAX_MSG_SIZE) throw SizeException()

    val header = ByteArray(3)
    header[0] = frameType.toByte()
    header[1] = payload.size.shr(8).and(255).toByte()
    header[2] = payload.size.and(255).toByte()

    conn.write(header)
    conn.write(payload)
}

/**
 * readMessage() is the protocol's main way of receiving data. Payloads can technically be up to
 * 2GiB in size, but data that large is not recommended to be sent this way.
 *
 * @throws BadFrameException when the frame header is invalid
 * @throws SizeException if the amount of data read does not match the size specified in the frame header
 * @throws BadSessionException if the client sends a multipart frame out of order.
 * @throws java.io.IOException if there was a network error
 */
fun readMessage(conn: InputStream): ByteArray {
    val out = mutableListOf<Byte>()
    val chunk = DataFrame()

    chunk.read(conn)
    when (chunk.type) {
        FrameType.SingleFrame -> {
            out.addAll(chunk.payload.toList())
            return out.toByteArray()
        }
        FrameType.MultipartFrameStart -> {}
        FrameType.MultipartFrameFinal -> throw BadSessionException()
        else -> throw BadFrameException()
    }

    // We got this far, so we have a multipart message which we need to reassemble.

    val totalSize = chunk.getMultipartSize()

    var sizeRead = 0
    while (sizeRead < totalSize) {
        chunk.read(conn)
        out.addAll(chunk.payload.toList())
        sizeRead += chunk.size

        if (chunk.type == FrameType.MultipartFrameFinal) break
    }

    return if (sizeRead == totalSize) out.toByteArray()
        else throw SizeException()
}

/**
 * Reads a received message as a string.
 *
 * @throws BadFrameException when the frame header is invalid
 * @throws SizeException if the amount of data read does not match the size specified in the frame header
 * @throws BadSessionException if the client sends a multipart frame out of order.
 * @throws java.io.IOException if there was a network error
 */
fun readStringMessage(conn: InputStream): String { return readMessage(conn).decodeToString() }

/**
 * writeMessage() is the protocol's main way of sending data. If the data is too large to fit into
 * an individual 64KiB frame, it is broken up and sent in parts. Messages can be up to 2GiB in size
 * but sending payloads that large is not recommended.
 *
 * @throws EmptyDataException if the payload is empty
 * @throws java.io.IOException if there was a network error
 */
fun writeMessage(conn: OutputStream, msg: ByteArray) {
    if (msg.isEmpty()) throw EmptyDataException()

    // If the packet is small enough to fit into a single frame, just send it and be done.
    if (msg.size < MAX_MSG_SIZE) {
        writeFrame(conn, FrameType.SingleFrame, msg)
        return
    }

    // If the message is bigger than the max message length, then we will send it as a multipart
    // message. This takes more work internally, but the benefits at the application level are
    // worth it. By using a binary wire format, we don't have to deal with serialization, escaping
    // and all sorts of other complications.

    // The initial message indicates that it is the start of a multipart message and contains the
    // total size in the payload as a string. All messages that follow contain the actual message
    // data.

    writeFrame(conn, FrameType.MultipartFrameStart, msg.size.toString().encodeToByteArray())
    var index = 0

    while (index + MAX_MSG_SIZE < msg.size) {
        writeFrame(conn, FrameType.MultipartFrame,
            msg.sliceArray(IntRange(index, index + MAX_MSG_SIZE - 1)))
        conn.flush()
        index += MAX_MSG_SIZE
    }

    writeFrame(conn, FrameType.MultipartFrameFinal, msg.sliceArray(IntRange(index, msg.size - 1)))
}

