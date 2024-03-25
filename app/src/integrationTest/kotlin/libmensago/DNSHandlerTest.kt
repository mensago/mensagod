package libmensago

import mensagod.DBConn
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import testsupport.FakeDNSHandler
import testsupport.SETUP_TEST_DATABASE
import testsupport.ServerTestEnvironment

class DNSHandlerTest {

    @Test
    fun lookupTests() {
        val dns = DNSHandler()
        var results = dns.lookupA("example.com").getOrThrow()
        assertEquals(1, results.size)
        assertEquals("/93.184.216.34", results[0].toString())

        results = dns.lookupAAAA("example.com").getOrThrow()
        assertEquals(1, results.size)
        assertEquals("/2606:2800:220:1:248:1893:25c8:1946", results[0].toString())

        val strResults = dns.lookupTXT("mensago.mensago.net").getOrThrow()
        assertEquals(2, strResults.size)
        assert(strResults[0].startsWith("pvk="))
        assert(strResults[1].startsWith("tls="))

        val srvResults = dns.lookupSRV("_mensago._tcp.mensago.net").getOrThrow()
        assertEquals(3, srvResults.size)
        assertEquals("mensago2.mensago.net", srvResults[1].server.toString())
    }

    @Test
    fun fakeLookupTests() {
        val env = ServerTestEnvironment("dns_fakelookup").provision(SETUP_TEST_DATABASE)
        DBConn.initialize(env.serverconfig)

        val dns = FakeDNSHandler()
        var results = dns.lookupA("example.com").getOrThrow()
        assertEquals(1, results.size)
        assertEquals("/127.0.0.1", results[0].toString())

        results = dns.lookupAAAA("example.com").getOrThrow()
        assertEquals(1, results.size)
        assertEquals("/0:0:0:0:0:0:0:1", results[0].toString())

        val strResults = dns.lookupTXT("mensago.example.com").getOrThrow()
        assertEquals(3, strResults.size)
        assert(strResults[0].startsWith("ek="))
        assert(strResults[1].startsWith("pvk="))

        val srvResults = dns.lookupSRV("_mensago._tcp.example.com").getOrThrow()
        assertEquals(2, srvResults.size)
        assertEquals("mensago2.example.com", srvResults[1].server.toString())
    }
}
