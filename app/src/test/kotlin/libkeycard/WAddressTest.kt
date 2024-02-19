package libkeycard

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class WAddressTest {

    @Test
    fun waddressTests() {
        assertNotNull(WAddress.fromString("5a56260b-aa5c-4013-9217-a78f094432c3/example.com"))
        assertNotNull(WAddress.fromMAddress(
            MAddress.fromString("5a56260b-aa5c-4013-9217-a78f094432c3/example.com")!!))
        assertNull(WAddress.fromString("cats4life/example.com"))
        assertNull(WAddress.fromMAddress(MAddress.fromString("cats4life/example.com")!!))
    }
}