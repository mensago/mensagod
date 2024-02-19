package libmensago

import keznacl.Base85
import libkeycard.RandomID
import libkeycard.Timestamp
import libkeycard.WAddress
import java.security.SecureRandom

/**
 * Message is primarily a data model class which also provides most of the functionality for
 * interacting with messages.
 *
 * @see SysMessage For interacting with system messages.
 * @see Envelope High-level API for encrypting messages.
 */
open class Message(var from: WAddress, var to: WAddress, var format: MsgFormat) {

    var date: Timestamp = Timestamp()
    var subject = ""
    var body = ""
    var cc: MutableSet<WAddress> = mutableSetOf()
    var bcc: MutableSet<WAddress> = mutableSetOf()
    var attachments = mutableListOf<Attachment>()

    var version = 1.0f
    var type = MsgType.User
    var subType: String? = null
    var id = RandomID.generate()
    var threadID = RandomID.generate()

    private val padding: String = makePadding(1..24)

    /**
     * Creates a reply to a source message. If quoting is not Quoting::None, each line in the
     * source message's body is indented with the same formatting as e-mail (`> `). The body format
     * from the previous message is retained. Pictures are retained if the message is quoted, but
     * not other attachments.
     */
    fun reply(quoting: QuoteType, replyAll: Boolean): Message {

        val out = Message(to, from, format)
        out.subject = if (subject.startsWith("re:", true))
            subject
        else
            "Re: $subject"

        if (quoting != QuoteType.None && body.isNotEmpty()) {
            out.body = body.trim().split("\r\n")
                .joinToString("\r\n", postfix = "\r\n", transform = { "> $it" })
        }
        if (replyAll) {
            out.cc = cc
            out.bcc = bcc
        }
        out.threadID = threadID
        out.attachments = attachments

        return out
    }

    /**
     * Forwards a source message. As with `reply()`, if quoting is not Quoting::None, each line in
     * the source message's body is indented and both the body format from the previous message
     * and any pictures are retained.
     */
    fun forward(recipient: WAddress): Message {
        val out = Message(to, recipient, format)
        out.subject = if (subject.startsWith("fwd:", true))
            subject
        else
            "Fwd: $subject"

        out.body = body.trim().split("\r\n")
            .joinToString("\r\n", postfix = "\r\n", transform = { "> $it" })
        out.threadID = threadID
        out.attachments = attachments

        return out
    }

    // Builder pattern methods

    fun setSubject(s: String): Message { subject = s; return this }

    fun setBody(s: String): Message { body = s; return this }

    fun addCC(recipient: WAddress): Message { cc.add(recipient); return this }
    fun clearCC(): Message { cc.clear(); return this }

    fun addBCC(recipient: WAddress): Message { bcc.add(recipient); return this }
    fun clearBCC(): Message { bcc.clear(); return this }

    fun attach(att: Attachment): Message { attachments.add(att); return this }
    fun clearAttachments(): Message { attachments.clear(); return this }

    companion object {

        /** Private method just for making padding strings of random characters */
        private fun makePadding(range: IntRange? = null): String {
            val actualRange = range ?: 1..24

            val rng = SecureRandom()
            val size = rng.nextInt(actualRange.first, actualRange.last + 1)
            return Base85.rfc1924Encoder.encode(
                ByteArray(size) { rng.nextInt(0, 256).toByte() }
            )
        }

    }
}
