package libmensago

import keznacl.EncryptionPair
import libkeycard.WAddress
import mensagod.DBConn
import mensagod.dbcmds.getEncryptionPair
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import testsupport.ADMIN_PROFILE_DATA
import testsupport.FakeDNSHandler
import testsupport.setupTest
import java.io.File
import java.time.Instant
import java.util.*

class EnvelopeTest {
    private val oneAddr = WAddress.fromString(
        "11111111-1111-1111-1111-111111111111/example.com"
    )!!
    private val adminAddr = WAddress.fromString(ADMIN_PROFILE_DATA["waddress"])!!

    @Test
    fun sealOpenTest() {
        val setupData = setupTest("envelope.sealOpen")

        val msg = Message(adminAddr, oneAddr, MsgFormat.Text)
            .setSubject("Test Message")
            .setBody("This message is just a test")

        val adminPair = EncryptionPair.fromStrings(
            ADMIN_PROFILE_DATA["encryption.public"]!!,
            ADMIN_PROFILE_DATA["encryption.private"]!!
        ).getOrThrow()
        adminPair.getPublicHash()

        val fakeDNS = FakeDNSHandler()
        KCCache.dns = fakeDNS
        val sealed = Envelope.seal(adminPair, msg).getOrThrow()

        val filelength = sealed.toStringResult().getOrThrow().length
        val filePath = listOf(
            setupData.testPath,
            "${Instant.now().epochSecond}.$filelength.${UUID.randomUUID().toString().lowercase()}"
        ).toPath().toString()
        sealed.saveFile(filePath)?.let { throw it }

        val loaded = Envelope.loadFile(File(filePath)).getOrThrow()
        val epair = getEncryptionPair(DBConn()).getOrThrow()

        loaded.tag.decryptSender(epair).getOrThrow()
        loaded.tag.decryptReceiver(epair).getOrThrow()

        val opened = loaded.open(adminPair).getOrThrow()
        assertEquals(opened.subject, "Test Message")
        assertEquals(opened.body, "This message is just a test")
        assertEquals(opened.from, adminAddr)
        assertEquals(opened.to, oneAddr)
    }
}