package keznacl

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class SigningTest {

    @Test
    fun algorithmSupportTest() {

        assert(isSupportedAlgorithm("ED25519"))
        val enc = getSupportedSigningAlgorithms()
        assertEquals(1, enc.size)
        assertEquals(CryptoType.ED25519, enc[0])

        assertEquals(CryptoType.ED25519, getPreferredSigningAlgorithm())
    }

    @Test
    fun pairSignTest() {
        val keypair = SigningPair.fromStrings(
            "ED25519:PnY~pK2|;AYO#1Z;B%T$2}E$^kIpL=>>VzfMKsDx",
            "ED25519:{^A@`5N*T%5ybCU%be892x6%*Rb2rnYd=SGeO4jF",
        ).getOrThrow()
        assertEquals(CryptoType.ED25519, keypair.getType())
        assertEquals(keypair.pubKey.value, "ED25519:PnY~pK2|;AYO#1Z;B%T$2}E$^kIpL=>>VzfMKsDx")
        assertEquals(keypair.privKey.value, "ED25519:{^A@`5N*T%5ybCU%be892x6%*Rb2rnYd=SGeO4jF")

        val testdata = "This is some signing test data"
        val signature = keypair.sign(testdata.toByteArray()).getOrThrow()
        val verified = keypair.verify(testdata.toByteArray(), signature).getOrThrow()
        assert(verified)

        val keypair2 = SigningPair.generate(CryptoType.ED25519).getOrThrow()
        val signature2 = keypair2.sign(testdata.toByteArray()).getOrThrow()
        val verified2 = keypair2.verify(testdata.toByteArray(), signature2).getOrThrow()
        assert(verified2)

        // Lint removal / smoke test
        CryptoString.fromString("ED25519:PnY~pK2|;AYO#1Z;B%T$2}E$^kIpL=>>VzfMKsDx")!!
            .toVerificationKey()
            .getOrThrow()
        CryptoString.fromString("ED25519:PnY~pK2|;AYO#1Z;B%T$2}E$^kIpL=>>VzfMKsDx")!!
            .getType()
    }

    @Test
    fun keySignTest() {
        val keypair = SigningPair.fromStrings(
            "ED25519:PnY~pK2|;AYO#1Z;B%T$2}E$^kIpL=>>VzfMKsDx",
            "ED25519:{^A@`5N*T%5ybCU%be892x6%*Rb2rnYd=SGeO4jF",
        ).getOrThrow()
        val key = VerificationKey.from(keypair.pubKey).getOrThrow()
        assertEquals(CryptoType.ED25519, key.getType())
        assertEquals(key.key.value, "ED25519:PnY~pK2|;AYO#1Z;B%T$2}E$^kIpL=>>VzfMKsDx")

        val testdata = "This is some signing test data"
        val signature = keypair.sign(testdata.toByteArray()).getOrThrow()
        val verified = key.verify(testdata.toByteArray(), signature).getOrThrow()
        assert(verified)
    }
}

