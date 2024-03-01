package libmensago

import keznacl.EncryptionPair
import libkeycard.WAddress
import libmensago.resolver.KCResolver
import mensagod.LocalFS
import mensagod.delivery.queueMessageForDelivery
import mensagod.gServerAddress
import mensagod.gServerDevID
import org.junit.jupiter.api.Test
import testsupport.ADMIN_PROFILE_DATA
import testsupport.FakeDNSHandler
import testsupport.setupTest
import java.lang.Thread.sleep

class DeliveryTest {

    @Test
    fun basicTest() {
        setupTest("delivery.basic")
        KCResolver.dns = FakeDNSHandler()

        val adminAddr = WAddress.fromString(ADMIN_PROFILE_DATA["waddress"])!!

        val msg = Message(gServerAddress, adminAddr, MsgFormat.Text)
            .setType(MsgType.System)
            .setSubType("delivertyreport")
            .setBody("Delivery Report: External Delivery Not Implemented")
            .setSubject(
                "The server was unable to deliver your message because external delivery" +
                        "is not yet implemented. Sorry!"
            )


        val adminPair = EncryptionPair.fromStrings(
            ADMIN_PROFILE_DATA["encryption.public"]!!,
            ADMIN_PROFILE_DATA["encryption.private"]!!
        ).getOrThrow()

        val sealed = Envelope.seal(adminPair, msg).getOrThrow()
            .toStringResult().getOrThrow()
        val lfs = LocalFS.get()
        val adminOutPath = MServerPath("/ out $gServerDevID")

        val outHandle = lfs.entry(MServerPath("/ out $gServerDevID"))
        outHandle.makeDirectory()?.let { throw it }

        val handle = lfs.makeTempFile(gServerDevID, sealed.length.toLong()).getOrThrow()
        handle.getFile().writeText(sealed)
        handle.moveTo(adminOutPath)?.let { throw it }
        val thread = queueMessageForDelivery(gServerAddress, adminAddr.domain, handle.path)
        sleep(100)

        thread.join()
    }
}