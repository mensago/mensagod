package keznacl

import org.junit.jupiter.api.Test

private class TestFailureException(message: String = "") : Exception(message)

class CryptoTypeTest {

    @Test
    fun basicTest() {
        listOf("CURVE25519", "ED25519", "SHA-256").forEach {
            if (!CryptoType.isSupported(it))
                throw TestFailureException("$it should be supported and wasn't")
        }

        assert(CryptoType.CURVE25519.isAsymmetric())
        assert(!CryptoType.XSALSA20.isAsymmetric())
        assert(CryptoType.ED25519.isSigning())
        assert(!CryptoType.BLAKE2B_256.isSigning())
        assert(CryptoType.XSALSA20.isSymmetric())
        assert(!CryptoType.CURVE25519.isSymmetric())
        assert(CryptoType.BLAKE2B_256.isHash())
        assert(!CryptoType.ED25519.isHash())
    }
}