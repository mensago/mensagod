package keznacl

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class HashTest {

    @Test
    fun testHashSupport() {
        assert(isSupportedAlgorithm("BLAKE2B-256"))
        val hashSupport = getSupportedHashAlgorithms()
        assertEquals(1, hashSupport.size)
        assertEquals("BLAKE2B-256", hashSupport[0])

        assertEquals("BLAKE2B-256", getPreferredHashAlgorithm())
    }

    @Test
    fun testBlake2B() {
        val expectedBlake = CryptoString.fromString(
            "BLAKE2B-256:?*e?y<{rF)B`7<5U8?bXQhNic6W4lmGlN}~Mu}la")!!
        assertEquals(expectedBlake.value, blake2Hash("aaaaaaaa".toByteArray()).getOrThrow().value)

        assertEquals(expectedBlake.value, hash("aaaaaaaa".toByteArray(), "BLAKE2B-256").
            getOrThrow().value)
    }

}