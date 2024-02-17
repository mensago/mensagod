package libmensago

import libkeycard.Domain
import libkeycard.RandomID
import libkeycard.WAddress
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import javax.activation.MimeType
import kotlin.test.assertEquals

class MessageTest {

    private val gLocalDomain = Domain.fromString("localhost.local")!!
    private val gLocalWID = RandomID.fromString("00000000-0000-0000-0000-000000000001")!!
    private val gLocalAddress = WAddress.fromParts(gLocalWID, gLocalDomain)

    private val gOneAddr = WAddress.fromString(
        "11111111-1111-1111-1111-111111111111/example.com")!!
    private val gTwoAddr = WAddress.fromString(
        "22222222-2222-2222-2222-222222222222/example.com")!!
    private val gSixAddr = WAddress.fromString(
        "66666666-6666-6666-6666-666666666666/example.com")!!

    private fun makeMsg(from: String = "", to: String = "", subject: String = "",
                        body: String = ""): Message {
        return Message(
            if (from.isNotEmpty()) WAddress.fromString(from)!! else gLocalAddress,
            if (to.isNotEmpty()) WAddress.fromString(from)!! else gLocalAddress,
            MsgFormat.Text
        )
            .setSubject(subject)
            .setBody(body)
    }

    @Test
    fun replyTest() {
        val msg = makeMsg()
            .setSubject("Reply Test")
            .setBody("First line\r\nSecond line\r\nThird line\r\n\r\n")
            .addCC(gOneAddr)
            .addCC(gTwoAddr)

        val noQuote = msg.reply(QuoteType.None, false)
        assert(noQuote.body.isEmpty())
        Assertions.assertEquals("Re: Reply Test", noQuote.subject)
        assert(noQuote.cc.isEmpty())

        msg.setSubject("re:Reply Test")
        Assertions.assertEquals("re:Reply Test",
            msg.reply(QuoteType.None, false).subject)

        val quoted = msg.reply(QuoteType.Top, true)
        assert(quoted.cc.isNotEmpty())
        Assertions.assertEquals(2, quoted.cc.size)
        assert(quoted.cc.containsAll(listOf(gOneAddr, gTwoAddr)))
        Assertions.assertEquals("> First line\r\n> Second line\r\n> Third line\r\n",
            quoted.body)
    }

    @Test
    fun forwardTest() {
        val msg = makeMsg()
            .setSubject("Forward Test")
            .setBody("First line\r\nSecond line\r\nThird line\r\n\r\n")
            .addCC(gOneAddr)
            .addCC(gTwoAddr)

        val fwd = msg.forward(gSixAddr)
        assert(fwd.cc.isEmpty())
        Assertions.assertEquals("Fwd: Forward Test", fwd.subject)
        Assertions.assertEquals("> First line\r\n> Second line\r\n> Third line\r\n",
            fwd.body)
    }

    @Test
    fun lintRemoval() {
        val msg = makeMsg()
            .setSubject("Lint Remover")
            .setBody("Empty body?\r\n")
            .addCC(gOneAddr)
            .addBCC(gTwoAddr)
            .clearCC()
            .clearBCC()
            .attach(Attachment("blank.txt", MimeType("text/plain"),
                "blank\r\n".encodeToByteArray())
            )
            .clearAttachments()

        assert(msg.threadID.toString().isNotEmpty())
        assertEquals(0, msg.bcc.size)
        assertEquals(0, msg.attachments.size)
    }
}
