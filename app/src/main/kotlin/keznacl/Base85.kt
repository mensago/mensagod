package keznacl

/*
    This is a stripped-down version of the Base85 code found in kbase85, having only the necessities
    to encode the RFC1924 variant of Base85 encoding, minimizing source changes.

    This code retains its original Apache 2.0 licensing.
 */

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.*
import kotlin.math.ceil

internal const val Power4: Long = 52200625 // 85^4
internal const val Power3: Long = 614125 // 85^3
internal const val Power2: Long = 7225 // 85^2

object Base85 {

    private var RFC1924ENCODER: Encoder? = null
    private var RFC1924DECODER: Decoder? = null

    val rfc1924Encoder: Encoder
        get() {
            if (RFC1924ENCODER == null) RFC1924ENCODER = Rfc1924Encoder()
            return RFC1924ENCODER!!
        }
    val rfc1924Decoder: Decoder
        get() {
            if (RFC1924DECODER == null) RFC1924DECODER = Rfc1924Decoder()
            return RFC1924DECODER!!
        }
}

open class Encoder(private val encodeMap: ByteArray) {

    open fun encodedLength(data: ByteArray, offset: Int = 0, length: Int = data.size): Int {
        require(!(offset < 0 || length < 0)) { "Offset and length must be non-negative" }
        return ceil(length * 1.25).toInt()
    }

    open fun encode(data: ByteArray, offset: Int = 0, length: Int = data.size): String {
        val out = ByteArray(encodedLength(data, offset, length))
        val len = encodeInternal(data, offset, length, out)
        return if (out.size == len) String(out) else String(out.copyOf(len))
    }

    fun encodeBlockReverse(rawData: ByteArray, offset: Int = 0, length: Int = rawData.size,
                           outOffset: Int = 0): String {
        val size = ceil(length * 1.25).toInt()
        val out = ByteArray(size)

        var data = rawData
        if (offset != 0 || length != data.size)
            data = data.copyOfRange(offset, offset + length)

        var sum = BigInteger(1, data)
        val b85 = BigInteger.valueOf(85)

        for (i in size + outOffset - 1 downTo outOffset) {
            val mod = sum.divideAndRemainder(b85)
            out[i] = encodeMap[mod[1].toInt()]
            sum = mod[0]
        }
        return String(out)
    }

    private fun encodeDangling(encodeMap: ByteArray, out: ByteArray, wi: Int, buffer: ByteBuffer,
                               leftover: Int): Int {
        var sum = buffer.getInt(0).toLong() and 0x00000000ffffffffL
        out[wi] = encodeMap[(sum / Power4).toInt()]
        sum %= Power4
        out[wi + 1] = encodeMap[(sum / Power3).toInt()]
        sum %= Power3
        if (leftover >= 2) {
            out[wi + 2] = encodeMap[(sum / Power2).toInt()]
            sum %= Power2
            if (leftover >= 3)
                out[wi + 3] = encodeMap[(sum / 85).toInt()]
        }
        return leftover + 1
    }

    protected open fun encodeInternal(`in`: ByteArray?, ri: Int, rlen: Int, out: ByteArray): Int {
        var rIndex = ri
        var wIndex = 0
        val buffer = ByteBuffer.allocate(4)
        val buf = buffer.array()
        val encodeMap = encodeMap
        var loop = rlen / 4
        while (loop > 0) {
            System.arraycopy(`in` as Any, rIndex, buf, 0, 4)
            wIndex = writeData(buffer.getInt(0).toLong() and 0x00000000ffffffffL,
                encodeMap, out, wIndex)
            loop--
            rIndex += 4
        }

        val leftover = rlen % 4
        if (leftover == 0) return wIndex

        buffer.putInt(0, 0)
        System.arraycopy(`in` as Any, rIndex, buf, 0, leftover)
        return wIndex + encodeDangling(encodeMap, out, wIndex, buffer, leftover)
    }

    protected open fun writeData(startSum: Long, map: ByteArray, out: ByteArray, wi: Int): Int {
        var sum = startSum
        out[wi] = map[(sum / Power4).toInt()]
        sum %= Power4
        out[wi + 1] = map[(sum / Power3).toInt()]
        sum %= Power3
        out[wi + 2] = map[(sum / Power2).toInt()]
        sum %= Power2
        out[wi + 3] = map[(sum / 85).toInt()]
        out[wi + 4] = map[(sum % 85).toInt()]
        return wi + 5
    }
}

class Rfc1924Encoder : Encoder(encoderMap) {
    companion object {
        val encoderMap = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"
            .toByteArray(StandardCharsets.US_ASCII)
    }
}

open class Decoder {

    open fun decodedLength(stringData: String, offset: Int = 0, length: Int = stringData.length):
            Int {
        
        return if (length % 5 == 1) -1 else (length * 0.8).toInt()
    }

    fun decode(stringData: String, offset: Int = 0, length: Int = stringData.length): ByteArray {

        val size = decodedLength(stringData, offset, length)
        if (size < 0)
            throw IllegalArgumentException("Malformed Base85/$name data")

        val result = ByteArray(size)
        try {
            val len = decodeInternal(stringData.toByteArray(StandardCharsets.US_ASCII), offset,
                length, result)

            // Should not happen, but fitting the size makes sure tests will fail when it does happen.
            if (result.size != len) return result.copyOf(len)
        } catch (ex: ArrayIndexOutOfBoundsException) {
            throw IllegalArgumentException("Malformed Base85/$name data", ex)
        }
        return result
    }

    fun decodeBlockReverse(data: String, offset: Int = 0, length: Int = data.length): ByteArray {

        var sum = BigInteger.ZERO
        val b85 = BigInteger.valueOf(85)
        val map = decodeMap
        try {
            var i = offset
            val len = offset + length
            while (i < len) {
                sum = sum.multiply(b85).add(BigInteger.valueOf(map[data[i].code].toLong()))
                i++
            }
        } catch (ex: ArrayIndexOutOfBoundsException) {
            return throw IllegalArgumentException("Malformed Base85/$name data", ex)
        }

        return sum.toByteArray()
    }

    open fun test(encodedString: String, offset: Int = 0, length: Int = encodedString.length):
            Boolean {

        val rawData = encodedString.toByteArray(StandardCharsets.US_ASCII)
        val valids = decodeMap
        try {
            var i = offset
            val len = offset + length
            while (i < len) {
                val e = rawData[i]
                if (valids[e.toInt()] < 0) return false
                i++
            }
            decodedLength(encodedString, offset, length)
        } catch (ex: ArrayIndexOutOfBoundsException) {
            return false
        } catch (ex: IllegalArgumentException) {
            return false
        }
        return true
    }

    private fun decodeDangling(decodeMap: ByteArray, `in`: ByteArray, ri: Int, buffer: ByteBuffer,
                                 leftover: Int): Int {
        if (leftover == 1)
            throw IllegalArgumentException("Malformed Base85/$name data", null)
        var sum = decodeMap[`in`[ri].toInt()] * Power4 + decodeMap[`in`[ri + 1].toInt()] * Power3 + 85
        if (leftover >= 3) {
            sum += decodeMap[`in`[ri + 2].toInt()] * Power2
            sum += if (leftover >= 4) (decodeMap[`in`[ri + 3].toInt()] * 85).toLong() else Power2
        } else sum += Power3 + Power2
        buffer.putInt(0, sum.toInt())
        return leftover - 1
    }

    protected open fun decodeInternal(data: ByteArray, ri: Int, rlen: Int, out: ByteArray): Int {

        var rIndex = ri
        var wIndex = 0
        val buffer = ByteBuffer.allocate(4)
        val buf = buffer.array()
        val decodeMap = decodeMap
        var loop = rlen / 5
        while (loop > 0) {
            putData(buffer, decodeMap, data, rIndex)
            System.arraycopy(buf, 0, out as Any, wIndex, 4)
            loop--
            wIndex += 4
            rIndex += 5
        }
        var leftover = rlen % 5
        if (leftover == 0) return wIndex
        leftover = decodeDangling(decodeMap, data, rIndex, buffer, leftover)
        System.arraycopy(buf, 0, out as Any, wIndex, leftover)
        return wIndex + leftover
    }

    private fun putData(buffer: ByteBuffer, map: ByteArray, `in`: ByteArray, ri: Int) {
        buffer.putInt(
            0,
            (map[`in`[ri].toInt()] * Power4 + map[`in`[ri + 1].toInt()] * Power3 + map[`in`[ri + 2].toInt()] * Power2 + map[`in`[ri + 3].toInt()] * 85 +
                    map[`in`[ri + 4].toInt()]).toInt()
        )
    }

    protected var decodeMap = ByteArray(127)
    protected open val name: String = ""
}

internal fun buildDecodeMap(encodeMap: ByteArray): ByteArray {
    val decodeMap = ByteArray(127)
    Arrays.fill(decodeMap, (-1).toByte())
    var i: Byte = 0
    val len = encodeMap.size.toByte()
    while (i < len) {
        val b = encodeMap[i.toInt()]
        decodeMap[b.toInt()] = i
        i++
    }

    return decodeMap
}

private val rfc1924DecoderMap: ByteArray = buildDecodeMap(Rfc1924Encoder.encoderMap)

class Rfc1924Decoder : Decoder() {
    override val name: String = "RFC1924"

    init {
        decodeMap = rfc1924DecoderMap
    }
}
