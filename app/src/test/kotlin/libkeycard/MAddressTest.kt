package libkeycard

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class MAddressTest {

    @Test
    fun maddressTests() {
        assertNotNull(MAddress.fromString("cats4life/example.com"))
        assertNotNull(MAddress.fromString("5a56260b-aa5c-4013-9217-a78f094432c3/example.com"))

        val waddr = WAddress.fromString("5a56260b-aa5c-4013-9217-a78f094432c3/example.com")!!
        assertEquals("5a56260b-aa5c-4013-9217-a78f094432c3/example.com", MAddress.fromWAddress(waddr).address)

        assertNull(MAddress.fromString("has spaces/example.com"))
        assertNull(MAddress.fromString("has_a_\"/example.com"))
        assertNull(MAddress.fromString("\\\\not_allowed/example.com"))
        assertNull(MAddress.fromString("/example.com"))
        assertNull(MAddress.fromString("5a56260b-aa5c-4013-9217-a78f094432c3/example.com/example.com"))
        assertNull(MAddress.fromString("5a56260b-aa5c-4013-9217-a78f094432c3"))
    }
}