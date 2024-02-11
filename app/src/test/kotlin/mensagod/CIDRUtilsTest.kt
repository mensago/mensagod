package mensagod

import keznacl.BadValueException
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class CIDRUtilsTest {

    @Test
    fun basicTest() {
        listOf(
            "192.168.10.10/24",
            "10.0.5.1/8",
            "fe80::5/16",
        ).forEach {
            if (CIDRUtils.fromString(it) == null)
                throw BadValueException("Failure to recognize good value $it")
        }

        val sn = CIDRUtils.fromString("192.168.1.0/24")!!
        assert(sn.isInRange("192.168.1.5").getOrThrow())
        assert(!sn.isInRange("192.168.10.5").getOrThrow())
        assertEquals("192.168.1.0", sn.networkAddress)
        assertEquals("192.168.1.255", sn.broadcastAddress)
    }
}