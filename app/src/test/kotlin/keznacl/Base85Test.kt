package keznacl

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class Base85Test {

    @Test
    fun encodeDecodeTest() {
        val testlist = listOf(
            Pair("a", "VE"),
            Pair("aa", "VPO"),
            Pair("aaa", "VPRn"),
            Pair("aaaa", "VPRom"),
            Pair("aaaaa", "VPRomVE"),
            Pair("aaaaaa", "VPRomVPO"),
            Pair("aaaaaaa", "VPRomVPRn"),
            Pair("aaaaaaaa", "VPRomVPRom"),
        )
        // Encoding tests
        testlist.forEach {
            val encoded = Base85.encode(it.first.encodeToByteArray())
            if (encoded != it.second)
                throw BadValueException(
                    "Test case failure: in: ${it.first}, wanted ${it.second}, got: $encoded"
                )
        }

        // Decoding tests
        testlist.forEach {
            val decoded = Base85.decode(it.second).getOrThrow().decodeToString()
            if (decoded != it.first)
                throw BadValueException(
                    "Test case failure: in: ${it.second}, wanted ${it.first}, got: $decoded"
                )
        }

        // Partly for testing, but mostly for lint removal
        assertEquals(5, Base85.encodedLength("aaaa".encodeToByteArray()))
        assertEquals(4, Base85.decodedLength("VPRom"))

        assert(Base85.test("abcdefg"))
        assert(!Base85.test("abc:defg"))
    }
}
