package mensagod.messaging

import keznacl.Base85
import libkeycard.RandomID
import libkeycard.Timestamp
import libkeycard.WAddress
import java.security.SecureRandom

/**
 * Class which represents a Mensago system message. It is not as full-featured as a class for a
 * Mensago client would be, as there is no need for support for attachments and other user-focused
 * features.
 */
class SysMessage(var from: WAddress, var to: WAddress, var subtype:String = "") {

    var version = 1.0f
    var type = "system"
    var id = RandomID.generate()
    var threadID = RandomID.generate()
    var format = "text"

    var date: Timestamp = Timestamp()
    var subject = ""
    var body = ""
    var randomString: String = makePadding(1..24)

    fun setBody(s: String): SysMessage { body = s; return this }
    fun setSubject(s: String): SysMessage { subject = s; return this }

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


