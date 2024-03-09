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
    }
}