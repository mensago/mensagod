package libmensago.resolver

import libkeycard.Domain
import libmensago.ServiceConfig
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class ServiceCacheTest {

    @Test
    fun basicTest() {

        val dom1 = Domain.fromString("example.com")!!
        val rec1 = listOf(ServiceConfig(dom1, 2001, 1))

        val dom2 = Domain.fromString("example2.com")!!
        val rec2 = listOf(ServiceConfig(dom2, 2002, 2))
        val dom3 = Domain.fromString("example3.com")!!
        val rec3 = listOf(ServiceConfig(dom3, 2003, 3))
        val dom4 = Domain.fromString("example4.com")!!
        val rec4 = listOf(ServiceConfig(dom4, 2004, 4))

        val cache = ServiceCache(3)
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
