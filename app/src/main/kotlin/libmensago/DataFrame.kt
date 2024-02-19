package libmensago

import keznacl.EmptyDataException
import java.io.InputStream
import java.io.OutputStream

const val MAX_MSG_SIZE: Int = 65532

// DataFrame is a structure for the lowest layer of network interaction. It represents a segment of
// data. Depending on the type code for the instance, it may indicate that the data payload is
// complete -- the SingleFrame type -- or it may be part of a larger set. In all cases a DataFrame
// is required to be equal to or smaller than the buffer size negotiated between the local host and
// the remote host.
class DataFrame {

    private var index = 0
    private val buffer = ByteArray(MAX_MSG_SIZE)

    var type: FrameType = FrameType.InvalidFrame

    val size: Int
        get() { return index }

    val payload: ByteArray
        get() { return buffer.sliceArray(IntRange(0, index - 1)) }

    fun getMultipartSize(): Result<Int> {
        if (size < 1) return Result.failure(BadFrameException())
        if (type != FrameType.MultipartFrameStart) return Result.failure(TypeException())

        return try { Result.success(payload.decodeToString().toInt()) }
        catch (e: Exception) { Result.failure(e) }
    }

    fun read(conn: InputStream): Throwable? {
        // Invalidate internal data in case we error out
        index = 0

        val header = ByteArray(3)
        var bytesRead = conn.read(header)
        if (bytesRead < 3) return BadFrameException()

        type = FrameType.fromByte(header[0])
        if (type == FrameType.InvalidFrame) return BadFrameException()

        // The size bytes are in network order (MSB), so this makes dealing with CPU architecture
        // much less of a headache regardless of what archictecture this is compiled for.

        // Once again, however, Java's complete lack of unsigned types come back to cause trouble.
        // Again. Which leads to more hoops to jump through.
        val payloadMSB = header[1].toUByte().toInt().shl(8)
        val payloadLSB = header[2].toUByte().toInt()
        val payloadSize = payloadMSB.or(payloadLSB)

        bytesRead = conn.read(buffer, 0, payloadSize)
        if (bytesRead != payloadSize)
            return SizeException()

        index = bytesRead

        return null
    }
}

fun writeFrame(conn: OutputStream, frameType: FrameType, payload: ByteArray): Throwable? {
    if (payload.size > MAX_MSG_SIZE) return SizeException()

    val header = ByteArray(3)
    header[0] = frameType.toByte()
    header[1] = payload.size.shr(8).and(255).toByte()
    header[2] = payload.size.and(255).toByte()

    try {
        conn.write(header)
        conn.write(payload)
    } catch (e: Exception) { return e }

    return null
}

fun readMessage(conn: InputStream): Result<ByteArray> {
    val out = mutableListOf<Byte>()
    val chunk = DataFrame()

    chunk.read(conn).let { if (it != null) return Result.failure(it) }
    when (chunk.type) {
        FrameType.SingleFrame -> {
            out.addAll(chunk.payload.toList())
            return Result.success(out.toByteArray())
        }
        FrameType.MultipartFrameStart -> {}
        FrameType.MultipartFrameFinal -> return Result.failure(BadSessionException())
        else -> return Result.failure(BadFrameException())
    }

    // We got this far, so we have a multipart message which we need to reassemble.

    val totalSize = chunk.getMultipartSize().getOrElse { return Result.failure(it) }

    var sizeRead = 0
    while (sizeRead < totalSize) {
        chunk.read(conn).let { if (it != null) return Result.failure(it) }
        out.addAll(chunk.payload.toList())
        sizeRead += chunk.size

        if (chunk.type == FrameType.MultipartFrameFinal) break
    }

    return if (sizeRead == totalSize) Result.success(out.toByteArray())
    else Result.failure(SizeException())
}

fun readStringMessage(conn: InputStream): Result<String> {
    val data = readMessage(conn).getOrElse { return Result.failure(it) }
    return Result.success(data.decodeToString())
}

fun writeMessage(conn: OutputStream, msg: ByteArray): Throwable? {
    if (msg.isEmpty()) return (EmptyDataException())

    // If the packet is small enough to fit into a single frame, just send it and be done.
    if (msg.size < MAX_MSG_SIZE) return writeFrame(conn, FrameType.SingleFrame, msg)

    // If the message is bigger than the max message length, then we will send it as a multipart
    // message. This takes more work internally, but the benefits at the application level are
    // worth it. By using a binary wire format, we don't have to deal with serialization, escaping
    // and all sorts of other complications.

    // The initial message indicates that it is the start of a multipart message and contains the
    // total size in the payload as a string. All messages that follow contain the actual message
    // data.

    writeFrame(conn, FrameType.MultipartFrameStart, msg.size.toString().toByteArray())
    var index = 0

    while (index + MAX_MSG_SIZE < msg.size) {
        writeFrame(conn, FrameType.MultipartFrame,
            msg.sliceArray(IntRange(index, index + MAX_MSG_SIZE - 1)))
        conn.flush()
        index += MAX_MSG_SIZE
    }

    writeFrame(conn, FrameType.MultipartFrameFinal, msg.sliceArray(IntRange(index, msg.size - 1)))
    return null
}
