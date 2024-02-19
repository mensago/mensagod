package libmensago

import keznacl.EncryptionPair
import keznacl.SecretKey
import libkeycard.WAddress
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class SealedDeliveryTagTest {

    private val gOneAddr = WAddress.fromString(
        "11111111-1111-1111-1111-111111111111/example.com")!!
    private val gTwoAddr = WAddress.fromString(
        "22222222-2222-2222-2222-222222222222/example.com")!!

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
        // TODO: Implement SealedDeliveryTagTest::readTest()
    }
}
