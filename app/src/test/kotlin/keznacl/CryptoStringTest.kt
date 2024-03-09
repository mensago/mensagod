package keznacl

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class CryptoStringTest {

    @Test
    fun constructionTests() {

        // Failure cases
        assert(!CryptoString.isValid("ThisIsFine"))
        assertNull(CryptoString.fromString(""))
        assertNull(CryptoString.fromString("ThisIsFine"))
        assertNull(
            CryptoString.fromString(
                "shouldBeAllCaps:r#r*RiXIN-0n)BzP3bv`LA&t4LFEQNF0Q@\$N~RF*"
            )
        )
        assertNull(CryptoString.fromString("ED25519"))
        assertNull(CryptoString.fromString(":123456789"))
        assertNull(CryptoString.fromString("\$ILLEGAL:123456789"))

        // Success cases
        assert(CryptoString.isValid("ED25519:r#r*RiXIN-0n)BzP3bv`LA&t4LFEQNF0Q@\$N~RF*"))
        assertNotNull(
            CryptoString.fromString(
                "ED25519:r#r*RiXIN-0n)BzP3bv`LA&t4LFEQNF0Q@\$N~RF*"
            )
        )
        assertNotNull(
            CryptoString.fromString(
                "BLAKE2B-256:-Zz4O7J;m#-rB)2llQ*xTHjtblwm&kruUVa_v(&W"
            )
        )
        assertNotNull(
            CryptoString.fromString(
                "CURVE25519:SNhj2K`hgBd8>G>lW$!pXiM7S-B!Fbd9jT2&{{Az"
            )
        )
        assert(CryptoString.checkFormat("CURVE25519:SNhj2K`hgBd8>G>lW$!pXiM7S-B!Fbd9jT2&{{Az"))
    }

    @Test
    fun conversionTests() {

        // Failure cases
        assertNull(CryptoString.fromBytes(CryptoType.XSALSA20, "".toByteArray()))

        val cs = CryptoString.fromBytes(CryptoType.XSALSA20, "aaaaaa".toByteArray())
        assertNotNull(cs)
        assertEquals("XSALSA20", cs.prefix)
        assertEquals("XSALSA20:VPRomVPO", cs.toString())
        assert("aaaaaa".toByteArray().contentEquals(cs.toRaw().getOrThrow()))
        assertNull(Hash.fromBytes(CryptoType.CURVE25519, "aaaaaa".toByteArray()))

        val expectedHash = hash("XSALSA20:VPRomVPO".encodeToByteArray()).getOrThrow()
        assertEquals(expectedHash.toString(), cs.hash().getOrThrow().toString())
    }
}
