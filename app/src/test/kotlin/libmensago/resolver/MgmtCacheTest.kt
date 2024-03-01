package libmensago.resolver

import keznacl.CryptoString
import libkeycard.Domain
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class MgmtCacheTest {

    @Test
    fun basicTest() {

        val dom1 = Domain.fromString("example.com")!!
        val rec1 = DNSMgmtRecord(
            CryptoString.fromString("PVK1:abcd")!!,
            CryptoString.fromString("SVK1:abcd")!!,
            CryptoString.fromString("EK1:abcd")!!, null
        )
        val dom2 = Domain.fromString("example2.com")!!
        val rec2 = DNSMgmtRecord(
            CryptoString.fromString("PVK2:abcd")!!,
            CryptoString.fromString("SVK2:abcd")!!,
            CryptoString.fromString("EK2:abcd")!!, null
        )
        val dom3 = Domain.fromString("example3.com")!!
        val rec3 = DNSMgmtRecord(
            CryptoString.fromString("PVK3:abcd")!!,
            CryptoString.fromString("SVK3:abcd")!!,
            CryptoString.fromString("EK3:abcd")!!, null
        )
        val dom4 = Domain.fromString("example4.com")!!
        val rec4 = DNSMgmtRecord(
            CryptoString.fromString("PVK4:abcd")!!,
            CryptoString.fromString("SVK4:abcd")!!,
            CryptoString.fromString("EK4:abcd")!!, null
        )

        val cache = MgmtCache(3)
        assertNull(cache.get(dom1))
        assertEquals("", cache.debugState())
        cache.put(dom1, rec1)
        assertEquals(rec1.toString(), cache.debugState())

        cache.put(dom2, rec2)
        assertEquals("$rec1\n$rec2", cache.debugState())
        cache.put(dom3, rec3)
        cache.put(dom4, rec4)
        assertEquals("$rec2\n$rec3\n$rec4", cache.debugState())
    }

}