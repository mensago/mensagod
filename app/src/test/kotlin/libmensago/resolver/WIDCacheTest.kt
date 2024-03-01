package libmensago.resolver

import libkeycard.MAddress
import libkeycard.RandomID
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class WIDCacheTest {

    @Test
    fun basicTest() {

        val addr1 = MAddress.fromString("csimons/example.com")!!
        val wid1 = RandomID.fromString("80b038b2-9faa-4a41-8dc5-c742bfb88923")!!
        val addr2 = MAddress.fromString("rbrannan/example.com")!!
        val wid2 = RandomID.fromString("4dcb13c6-9b1a-4da0-8fbc-a444dfbb622f")!!
        val addr3 = MAddress.fromString("cavs4life/example.com")!!
        val wid3 = RandomID.fromString("5fef892b-4c2c-4500-8a5a-d52946dcd8f0")!!
        val addr4 = MAddress.fromString("ICanHazKittehs/example.com")!!
        val wid4 = RandomID.fromString("e9e12372-f029-46c3-a7db-de3e11b4032b")!!

        val cache = WIDCache(3)
        assertNull(cache.get(addr1))
        assertEquals("", cache.debugState())
        cache.put(addr1, wid1)
        assertEquals(wid1.toString(), cache.debugState())

        cache.put(addr2, wid2)
        assertEquals("$wid1\n$wid2", cache.debugState())
        cache.put(addr3, wid3)
        cache.put(addr4, wid4)
        assertEquals("$wid2\n$wid3\n$wid4", cache.debugState())
    }

}