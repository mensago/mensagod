package libmensago

import keznacl.EncryptionPair
import keznacl.SecretKey
import libkeycard.WAddress
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import testsupport.ADMIN_PROFILE_DATA
import testsupport.FakeDNSHandler
import testsupport.setupTest
import java.time.Instant
import java.util.*

class SealedDeliveryTagTest {

    private val gOneAddr = WAddress.fromString(
        "11111111-1111-1111-1111-111111111111/example.com"
    )!!
    private val gTwoAddr = WAddress.fromString(
        "22222222-2222-2222-2222-222222222222/example.com"
    )!!

    @Test
    fun basicTest() {
        // This test actually covers both DeliveryTag and SealedDeliveryTag

        val tag = DeliveryTag.new(gOneAddr, gTwoAddr, MsgType.System, "test").getOrThrow()

        val recipientKey = SecretKey.generate().getOrThrow()
        val senderKey = EncryptionPair.generate().getOrThrow()
        val receiverKey = EncryptionPair.generate().getOrThrow()

        val sealed = tag.seal(recipientKey, senderKey, receiverKey).getOrThrow()

        val rInfo = sealed.decryptReceiver(receiverKey).getOrThrow()
        assertEquals(gTwoAddr, rInfo.to)
        assertEquals(gOneAddr.domain, rInfo.senderDom)

        val sInfo = sealed.decryptSender(senderKey).getOrThrow()
        assertEquals(gOneAddr, sInfo.from)
        assertEquals(gTwoAddr.domain, sInfo.recipientDom)
    }

    @Test
    fun readTest() {
        val setupData = setupTest("sealedDeliveryTag.read")

        val msg = Message(gOneAddr, gTwoAddr, MsgFormat.Text)
            .setSubject("A Message")
            .setBody("We're just testing here ")

        val adminPair = EncryptionPair.fromStrings(
            ADMIN_PROFILE_DATA["encryption.public"]!!,
            ADMIN_PROFILE_DATA["encryption.private"]!!
        ).getOrThrow()
        adminPair.getPublicHash()

        val sealed = Envelope.seal(adminPair, msg, FakeDNSHandler()).getOrThrow()

        val filelength = sealed.toStringResult().getOrThrow().length
        val filePath = listOf(
            setupData.testPath,
            "${Instant.now().epochSecond}.$filelength.${UUID.randomUUID().toString().lowercase()}"
        ).toPath()
        sealed.saveFile(filePath.toString())?.let { throw it }

        val tag = SealedDeliveryTag.readFromFile(filePath.toFile()).getOrThrow()
        assertEquals(tag.type, sealed.tag.type)
        assertEquals(tag.receiver, sealed.tag.receiver)
        assertEquals(tag.sender, sealed.tag.sender)
        assertEquals(tag.payloadKey, sealed.tag.payloadKey)
        assertEquals(tag.keyHash, sealed.tag.keyHash)
        assertEquals(tag.date, sealed.tag.date)
        assertEquals(tag.subType, sealed.tag.subType)
        assertEquals(tag.version, sealed.tag.version)
    }
}
