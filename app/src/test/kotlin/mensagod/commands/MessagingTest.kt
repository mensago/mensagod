package mensagod.commands

import libmensago.ClientRequest
import libmensago.FrameType
import libmensago.ServerResponse
import libmensago.writeMessage
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals

class MessagingTest {
    @Test
    fun testClientResponseSend() {
        val outStream = ByteArrayOutputStream(500)
        val msg = ClientRequest("TEST", mutableMapOf("foo" to "bar"))

        // eliminate IDEA warning that action property is not used.
        assert(msg.action.isNotEmpty())

        msg.send(outStream)

        val buffer = outStream.toByteArray()
        assertEquals(FrameType.SingleFrame, FrameType.fromByte(buffer[0]))

        assertEquals("""{"Action":"TEST","Data":{"foo":"bar"}}""",
            buffer.sliceArray(IntRange(3, buffer.size - 1)).decodeToString())
    }

    @Test
    fun testServerResponse() {
        val testData = """{"Code":200,"Status":"OK","Info":"test","Data":{"foo":"bar"}}"""
        val outStream = ByteArrayOutputStream(500)
        writeMessage(outStream, testData.toByteArray())


        // receive()
        val buffer = outStream.toByteArray()
        val inStream = ByteArrayInputStream(buffer)
        val response = ServerResponse.receive(inStream).getOrThrow()
        assertEquals(200, response.code)
        assertEquals("OK", response.status)
        assertEquals("test", response.info)
        assert(response.data.containsKey("foo"))
        assertEquals("bar", response.data["foo"])

        // toStatus()
        val status = response.toStatus()
        assertEquals(200, status.code)
        assertEquals("OK", status.description)
        assertEquals("test", status.info)

        // checkFields()
        val schema = listOf(Pair("foo",true), Pair("optional", false))
        assert(response.checkFields(schema))

        val failSchema = listOf(Pair("foo",true), Pair("missing", true))
        assert(!response.checkFields(failSchema))
    }
}