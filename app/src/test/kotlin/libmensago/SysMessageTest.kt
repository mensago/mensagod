package libmensago

import libkeycard.WAddress
import org.junit.jupiter.api.Test

class SysMessageTest {
    private val gOneAddr = WAddress.fromString(
        "11111111-1111-1111-1111-111111111111/example.com")!!
    private val gTwoAddr = WAddress.fromString(
        "22222222-2222-2222-2222-222222222222/example.com")!!

    @Test
    fun lintRemoval() {
        val msg = SysMessage(gOneAddr, gTwoAddr, "conreq.1")
        assert(msg.subtype.isNotEmpty())
    }
}
