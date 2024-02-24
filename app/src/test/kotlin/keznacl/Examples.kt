package keznacl

import org.junit.jupiter.api.Test

class Examples {

    @Test
    fun secretKeyEncryptionExample() {
        val mySecretKey = SecretKey.generate().getOrThrow()
        val keyHash = mySecretKey.getHash().getOrThrow()
        val msg = "One if by land, two if by sea"

        val encryptedData = mySecretKey.encrypt(msg.encodeToByteArray()).getOrThrow()
        println("My secret message:\n$msg\n")
        println("My encrypted secret message:\n$encryptedData\n")
        println("The hash of my secret key:\n$keyHash\n")
    }
}