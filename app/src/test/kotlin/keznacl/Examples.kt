package keznacl

import org.junit.jupiter.api.Test

class Examples {
    @Test
    fun secretKeyEncryptionExample() {
        // This example just shows how simple it is to encrypt arbitrary data with the library.

        val mySecretKey = SecretKey.generate().getOrThrow()
        val keyHash = mySecretKey.getHash().getOrThrow()
        val msg = "One if by land, two if by sea"

        val encryptedData = mySecretKey.encrypt(msg).getOrThrow()
        println("My secret message:\n$msg\n")
        println("My encrypted secret message:\n$encryptedData\n")
        println("The hash of my secret key:\n$keyHash\n")
    }

    @Test
    fun asymmetricEncryptionExample() {
        // Here we do the same kind of thing, but with an asymmetric encryption keypair. Note that
        // this kind of encryption is slower, so it shouldn't be used for large chunks of data.

        // In this case, we're using the keypair as a Key Encryption Mechanism, where a SecretKey
        // is used to encrypt the data itself because it's faster, and the keypair is used to
        // encrypt the SecretKey itself.

        val myKeyPair = EncryptionPair.generate().getOrThrow()
        val messageKey = SecretKey.generate().getOrThrow()
        val msg = "When the whole world is running towards a cliff, he who is running in the " +
                "opposite direction appears to have lost his mind. -- C.S. Lewis"

        val encryptedData = messageKey.encrypt(msg).getOrThrow()

        // EncryptionPair's wrap() and unwrap() methods were designed explicitly for encrypting
        // and decrypting SecretKey instances.
        val encryptedKey = myKeyPair.wrap(messageKey).getOrThrow()
        println("My secret message:\n$msg\n")
        println("My encrypted secret message:\n$encryptedData\n")
        println("My message's encrypted encryption key: \n$encryptedKey")

        // The advantage to the library's API design is that decrypting the message is pretty
        // elegant using functional programming style.
        val myDecryptedMessage = myKeyPair.unwrap(encryptedKey).getOrThrow()
            .decryptString(encryptedData).getOrThrow()
        println("My decrypted message: \n$myDecryptedMessage")
    }

}