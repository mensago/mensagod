package keznacl

import kotlinx.serialization.Serializable
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class JSONSupportTest {

    @Serializable
    class JsonTest(val foo: Int, val bar: Int)

    @Test
    fun supportTest() {
        val testdata = JsonTest(1, 2)
        val key =
            SecretKey.fromString("XSALSA20:Z%_Is*V6uc!_+QIG5F`UJ*cLYoO`=58RCuAk-`Bq")
                .getOrThrow()

        val encData = serializeAndEncrypt(testdata, key).getOrThrow()
        val thawedData = decryptAndDeserialize<JsonTest>(encData, key).getOrThrow()
        assertEquals(testdata.foo, thawedData.foo)
        assertEquals(testdata.bar, thawedData.bar)
    }
}
