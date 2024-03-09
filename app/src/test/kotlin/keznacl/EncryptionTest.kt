package keznacl

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class EncryptionTest {

    @Test
    fun algorithmSupportTest() {

        assert(isSupportedAlgorithm("CURVE25519"))
        val enc = getSupportedAsymmetricAlgorithms()
        assertEquals(1, enc.size)
        assertEquals(CryptoType.CURVE25519, enc[0])

        assertEquals(CryptoType.CURVE25519, getPreferredAsymmetricAlgorithm())
    }

    @Test
    fun pairEncryptTest() {
        val keypair = EncryptionPair.fromStrings(
            "CURVE25519:(B2XX5|<+lOSR>_0mQ=KX4o<aOvXe6M`Z5ldINd`",
            "CURVE25519:(Rj5)mmd1|YqlLCUP0vE;YZ#o;tJxtlAIzmPD7b&"
        ).getOrThrow()
        assertEquals(CryptoType.CURVE25519, keypair.getType())

        assertEquals(keypair.pubKey.value, "CURVE25519:(B2XX5|<+lOSR>_0mQ=KX4o<aOvXe6M`Z5ldINd`")
        assertEquals(
            keypair.privKey.value,
            "CURVE25519:(Rj5)mmd1|YqlLCUP0vE;YZ#o;tJxtlAIzmPD7b&"
        )

        val testdata = "This is some encryption test data"
        val encdata = keypair.encrypt(testdata.toByteArray()).getOrThrow()
        val decdata = keypair.decrypt(encdata)
        assert(decdata.isSuccess)

        val keypair2 = EncryptionPair.generate(CryptoType.CURVE25519).getOrThrow()
        val encdata2 = keypair2.encrypt(testdata.toByteArray()).getOrThrow()
        val decdata2 = keypair2.decrypt(encdata2)
        assert(decdata2.isSuccess)

        // Smoke test / lint removal
        keypair.getPublicHash().getOrThrow()
        CryptoString.fromString("CURVE25519:(B2XX5|<+lOSR>_0mQ=KX4o<aOvXe6M`Z5ldINd`")!!
            .toEncryptionKey()
            .getOrThrow()
    }

    @Test
    fun keyEncryptTest() {
        val keypair = EncryptionPair.fromStrings(
            "CURVE25519:(B2XX5|<+lOSR>_0mQ=KX4o<aOvXe6M`Z5ldINd`",
            "CURVE25519:(Rj5)mmd1|YqlLCUP0vE;YZ#o;tJxtlAIzmPD7b&"
        ).getOrThrow()
        val key = EncryptionKey.fromString(keypair.pubKey.toString()).getOrThrow()
        assertEquals(key.key.value, "CURVE25519:(B2XX5|<+lOSR>_0mQ=KX4o<aOvXe6M`Z5ldINd`")

        val testdata = "This is some encryption test data"
        val encdata = key.encrypt(testdata.toByteArray()).getOrThrow()
        val decdata = keypair.decrypt(encdata)
        assert(decdata.isSuccess)
    }
}