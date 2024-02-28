package keznacl

/*
    This is based on sheep-y's Java implementation of Base85 (https://github.com/Sheep-y/Base85),
    although it bears little resemblance to the original. The base implementation was translated
    into Kotlin, converted to return exceptions instead of throwing them, and stripped down to only
    have the necessities to encode and decode the RFC1924 variant of Base85 encoding.

    This code retains its original Apache 2.0 licensing.
 */

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.*
import kotlin.math.ceil


object Base85 {
    private const val POWER4: Long = 52200625 // 85^4
    private const val POWER3: Long = 614125 // 85^3
    private const val POWER2: Long = 7225 // 85^2

    private val encoderMap =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"
            .toByteArray(StandardCharsets.US_ASCII)
    private var decodeMap = buildDecodeMap()

    /**
     * Encodes the given binary data into the RFC1924 variant of Base85 encoding, which will be 20%
     * larger than the original data.
     */
    fun encode(data: ByteArray): String {
        val out = ByteArray(encodedLength(data))
        val len = encodeInternal(data, data.size, out)
        return if (out.size == len) String(out) else String(out.copyOf(len))
    }

    /** Returns the length, in bytes, of the data after encoding */
    fun encodedLength(data: ByteArray): Int {
        return ceil(data.size * 1.25).toInt()
    }

    /**
     * Decodes a string containing data using the RFC1924 variant of Base85 encoding. The output
     * will be 20% smaller than the encoded string.
     *
     * @exception IllegalArgumentException Returned on decoding errors
     */
    fun decode(stringData: String): Result<ByteArray> {

        val decodedSize = decodedLength(stringData)
        if (decodedSize < 0)
            return Result.failure(IllegalArgumentException("Malformed Base85/RFC1924 data"))

        val out = ByteArray(decodedSize)
        decodeInternal(stringData.toByteArray(StandardCharsets.US_ASCII), out)
            .getOrElse { return it.toFailure() }

        return out.toSuccess()
    }

    /** Returns the length of the data returned after decoding */
    fun decodedLength(stringData: String): Int {
        return if (stringData.length % 5 == 1) -1 else (stringData.length * 0.8).toInt()
    }

    /** Verifies that the passed string contains valid Base85-encoded data */
    fun test(encodedString: String): Boolean {

        val rawData = encodedString.toByteArray(StandardCharsets.US_ASCII)

        for (i in encodedString.indices) {
            val e = rawData[i]
            if (decodeMap[e.toInt()] < 0) return false
        }

        return true
    }

    private fun decodeRemainder(
        decodeMap: ByteArray, `in`: ByteArray, ri: Int, buffer: ByteBuffer,
        leftover: Int
    ): Result<Int> {
        if (leftover == 1)
            return Result.failure(IllegalArgumentException("Malformed Base85/RFC1924 data", null))
        var sum =
            decodeMap[`in`[ri].toInt()] * POWER4 + decodeMap[`in`[ri + 1].toInt()] * POWER3 + 85
        if (leftover >= 3) {
            sum += decodeMap[`in`[ri + 2].toInt()] * POWER2
            sum += if (leftover >= 4) (decodeMap[`in`[ri + 3].toInt()] * 85).toLong() else POWER2
        } else
            sum += POWER3 + POWER2
        buffer.putInt(0, sum.toInt())
        return Result.success(leftover - 1)
    }

    private fun decodeInternal(inData: ByteArray, outData: ByteArray): Result<Int> {
        var rIndex = 0
        var wIndex = 0
        val buffer = ByteBuffer.allocate(4)
        val buf = buffer.array()
        val decodeMap = decodeMap
        var loop = inData.size / 5
        while (loop > 0) {
            putData(buffer, decodeMap, inData, rIndex)
            System.arraycopy(buf, 0, outData as Any, wIndex, 4)
            loop--
            wIndex += 4
            rIndex += 5
        }
        var leftover = inData.size % 5
        if (leftover == 0) return Result.success(wIndex)
        leftover = decodeRemainder(decodeMap, inData, rIndex, buffer, leftover)
            .getOrElse { return it.toFailure() }
        System.arraycopy(buf, 0, outData as Any, wIndex, leftover)
        return Result.success(wIndex + leftover)
    }

    private fun putData(buffer: ByteBuffer, map: ByteArray, inData: ByteArray, ri: Int) {
        buffer.putInt(
            0, (map[inData[ri].toInt()] * POWER4 +
                    map[inData[ri + 1].toInt()] * POWER3 +
                    map[inData[ri + 2].toInt()] * POWER2 +
                    map[inData[ri + 3].toInt()] * 85 +
                    map[inData[ri + 4].toInt()]).toInt()
        )
    }

    private fun encodeRemainder(
        encodeMap: ByteArray, out: ByteArray, writeIndex: Int, buffer: ByteBuffer,
        leftover: Int
    ): Int {
        var sum = buffer.getInt(0).toLong() and 0x00000000ffffffffL
        out[writeIndex] = encodeMap[(sum / POWER4).toInt()]
        sum %= POWER4
        out[writeIndex + 1] = encodeMap[(sum / POWER3).toInt()]
        sum %= POWER3
        if (leftover >= 2) {
            out[writeIndex + 2] = encodeMap[(sum / POWER2).toInt()]
            sum %= POWER2
            if (leftover >= 3)
                out[writeIndex + 3] = encodeMap[(sum / 85).toInt()]
        }
        return leftover + 1
    }

    private fun encodeInternal(inData: ByteArray?, length: Int, out: ByteArray): Int {
        var rIndex = 0
        var wIndex = 0
        val buffer = ByteBuffer.allocate(4)
        val buf = buffer.array()
        val encodeMap = encoderMap
        var loop = length / 4
        while (loop > 0) {
            System.arraycopy(inData as Any, rIndex, buf, 0, 4)
            wIndex = writeData(
                buffer.getInt(0).toLong() and 0x00000000ffffffffL,
                encodeMap, out, wIndex
            )
            loop--
            rIndex += 4
        }

        val leftover = length % 4
        if (leftover == 0) return wIndex

        buffer.putInt(0, 0)
        System.arraycopy(inData as Any, rIndex, buf, 0, leftover)
        return wIndex + encodeRemainder(encodeMap, out, wIndex, buffer, leftover)
    }

    private fun writeData(
        startSum: Long,
        encodeMap: ByteArray,
        out: ByteArray,
        writeIndex: Int
    ): Int {
        var sum = startSum
        out[writeIndex] = encodeMap[(sum / POWER4).toInt()]
        sum %= POWER4
        out[writeIndex + 1] = encodeMap[(sum / POWER3).toInt()]
        sum %= POWER3
        out[writeIndex + 2] = encodeMap[(sum / POWER2).toInt()]
        sum %= POWER2
        out[writeIndex + 3] = encodeMap[(sum / 85).toInt()]
        out[writeIndex + 4] = encodeMap[(sum % 85).toInt()]
        return writeIndex + 5
    }

    private fun buildDecodeMap(): ByteArray {
        val out = ByteArray(127)
        Arrays.fill(out, (-1).toByte())
        var i: Byte = 0
        val len = encoderMap.size.toByte()
        while (i < len) {
            val b = encoderMap[i.toInt()]
            out[b.toInt()] = i
            i++
        }

        return out
    }
}
