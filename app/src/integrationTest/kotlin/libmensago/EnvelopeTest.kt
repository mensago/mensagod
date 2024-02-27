package libmensago

import keznacl.EncryptionKey
import libkeycard.WAddress
import org.junit.jupiter.api.Test
import testsupport.ADMIN_PROFILE_DATA
import testsupport.FakeDNSHandler
import testsupport.setupTest
import java.time.Instant
import java.util.*

class EnvelopeTest {
    private val oneWID = WAddress.fromString(
        "11111111-1111-1111-1111-111111111111/example.com"
    )!!
    private val adminWID = WAddress.fromString(ADMIN_PROFILE_DATA["waddress"])!!

    @Test
    fun sealOpenTest() {
        val setupData = setupTest("envelope.sealOpen")

        val msg = Message(adminWID, oneWID, MsgFormat.Text)
            .setSubject("Test Message")
            .setBody("This message is just a test")

        val adminKey = EncryptionKey.fromString(ADMIN_PROFILE_DATA["encryption.public"]!!)
            .getOrThrow()
        val sealed = Envelope.seal(adminKey, msg, FakeDNSHandler()).getOrThrow()

        val filelength = sealed.toString().length
        val filename =
            "${Instant.now().epochSecond}.$filelength.${UUID.randomUUID().toString().lowercase()}"
        sealed.saveFile(listOf(setupData.testPath, filename).toPath().toString())


        // TODO: Implement sealOpenTest
    }
}