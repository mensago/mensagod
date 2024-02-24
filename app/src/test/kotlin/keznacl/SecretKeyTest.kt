package keznacl

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class SecretKeyTest {

    @Test
    fun testSymmetricSupport() {
        assert(isSupportedAlgorithm("XSALSA20"))
        val symSupport = getSupportedSymmetricAlgorithms()
        assertEquals(1, symSupport.size)
        assertEquals("XSALSA20", symSupport[0])

        assertEquals("XSALSA20", getPreferredSymmetricAlgorithm())
    }

    @Test
    fun testSecretKey() {
        val testdata = "This is some test data"
        val key =
            SecretKey.fromString("XSALSA20:Z%_Is*V6uc!_+QIG5F`UJ*cLYoO`=58RCuAk-`Bq")
                .getOrThrow()

        val encdata = key.encrypt(testdata.toByteArray()).getOrThrow()
        val decdata = key.decrypt(encdata)
        assert(decdata.isSuccess)

        assertEquals(key.key.value, "XSALSA20:Z%_Is*V6uc!_+QIG5F`UJ*cLYoO`=58RCuAk-`Bq")

        val key2 = SecretKey.generate("XSALSA20").getOrThrow()
        val encdata2 = key2.encrypt(testdata.toByteArray()).getOrThrow()
        val decdata2 = key2.decrypt(encdata2)
        assert(decdata2.isSuccess)

        // Lint removal / smoke test
        CryptoString.fromString("XSALSA20:Z%_Is*V6uc!_+QIG5F`UJ*cLYoO`=58RCuAk-`Bq")!!
            .toSecretKey().getOrThrow()
    }

}