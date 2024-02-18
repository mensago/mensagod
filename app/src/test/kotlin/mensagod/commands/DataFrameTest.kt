package mensagod.commands

import libmensago.*
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import kotlin.test.assertEquals

class DataFrameTest {

    @Test
    fun basics() {
        val testData = byteArrayOf(50, 0, 4, 65, 66, 67, 68)
        val stream = ByteArrayInputStream(testData)

        val frame = DataFrame()
        frame.read(stream)

        assertEquals(FrameType.SingleFrame, frame.type)
        assertEquals(4, frame.size)
        assertEquals("ABCD", frame.payload.decodeToString())
    }

    @Test
    fun frameSession() {
        val msg = "ThisIsATestMessage"
        val outStream = ByteArrayOutputStream(30)
        writeMessage(outStream, msg.encodeToByteArray())

        val outmsg = readStringMessage(ByteArrayInputStream(outStream.toByteArray()))
        assert(msg == outmsg)
    }

    private fun generateMultipartMsg(): String {
        val sj = StringBuilder("")
        val multiplier = (MAX_MSG_SIZE / 33) + 1
        for (i in 1 .. multiplier)
            sj.append("|${i.toString().padStart(4,'0')}|ABCDEFGHIJKLMNOPQRSTUVWXYZ ")
        return sj.toString()
    }

    @Test
    fun writeMultipartMsg() {
        val sentMsg = generateMultipartMsg()

        val outStream = ByteArrayOutputStream(sentMsg.length * 2)
        writeMessage(outStream, sentMsg.encodeToByteArray())

        val frame = DataFrame()
        val inBuffer = outStream.toByteArray()
        val inStream = ByteArrayInputStream(inBuffer)

        // First, get the first data frame, which should be of type MultipartMessageStart and the
        // payload should contain a decimal string of the size of the complete message size.

        frame.read(inStream)
        assertEquals(FrameType.MultipartFrameStart, frame.type)
        assertEquals(sentMsg.length.toString(), frame.payload.decodeToString())

        val totalSize = frame.getMultipartSize()
        assertEquals(sentMsg.length, totalSize)

        val msgParts = mutableListOf<Byte>()

        // Now get and process the first actual data frame
        frame.read(inStream)
        assertEquals(FrameType.MultipartFrame, frame.type)
        assertEquals(sentMsg.substring(IntRange(0, MAX_MSG_SIZE -1)).length,
            frame.payload.decodeToString().length)
        assertEquals(sentMsg.substring(IntRange(0, MAX_MSG_SIZE -1)), frame.payload.decodeToString())
        msgParts.addAll(frame.payload.toList())

        // Finally deal with the final frame
        frame.read(inStream)
        assertEquals(FrameType.MultipartFrameFinal, frame.type)
        msgParts.addAll(frame.payload.toList())

        // SysMessage data received from both data frames and complete. Now reassemble, check total
        // size, and confirm value match.
        val receivedMsg = msgParts.toByteArray().decodeToString()
        assertEquals(sentMsg, receivedMsg)
    }

    @Test
    fun readMultipartMsg() {
        val testData = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        val multiplier = (MAX_MSG_SIZE / testData.length) + 1
        val sentMsg = testData.repeat(multiplier)
        val outStream = ByteArrayOutputStream(sentMsg.length * 2)
        writeMessage(outStream, sentMsg.encodeToByteArray())

        val receivedMsg = readStringMessage(ByteArrayInputStream(outStream.toByteArray()))
        assert(sentMsg == receivedMsg)
    }
}