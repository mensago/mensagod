package keznacl

import com.iwebpp.crypto.TweetNaclFast.SecretBox
import kotlinx.serialization.Serializable
import java.security.SecureRandom

/**
 * Returns the symmetric encryption algorithms supported by the library. Currently the only
 * supported algorithm is XSALSA20. Other algorithms may be added at a future time.
 */
fun getSupportedSymmetricAlgorithms(): List<String> {
    return listOf("XSALSA20")
}

/**
 * Returns the recommended secret key encryption algorithm supported by the library. If you don't
 * know what to choose for your implementation, this will provide a good default which balances
 * speed and security.
 */
fun getPreferredSymmetricAlgorithm(): String {
    return "XSALSA20"
}

/**
 * The SecretKey class implements symmetric encryption.
 */
@Serializable
class SecretKey private constructor(val key: CryptoString) : Encryptor, Decryptor {

    /**
     * Returns a [Hash] of the key using the specified algorithm.
     *
     * @exception UnsupportedAlgorithmException Returned if the library does not support the
     * algorithm specified by the keys
     */
    fun getHash(algorithm: String = getPreferredHashAlgorithm()): Result<Hash> {
        return getPublicHash(algorithm)
    }

    /**
     * Required function for the Encryptor interface. It merely calls getHash() internally.
     */
    override fun getPublicHash(algorithm: String): Result<Hash> {
        return key.hash(algorithm)
    }

    /**
     * Encrypts the data passed to it.
     *
     * @exception EncryptionFailureException Returned if there was an internal error encrypting the data
     * @exception IllegalArgumentException Returned if there was a key decoding error
     */
    override fun encrypt(data: ByteArray): Result<CryptoString> {
        val rawKey = key.toRaw().getOrElse { return it.toFailure() }
        val box = SecretBox(rawKey)

        val rng = SecureRandom()
        val nonce = ByteArray(SecretBox.nonceLength)
        rng.nextBytes(nonce)

        val ciphertext: ByteArray =
            box.box(data, nonce) ?: return Result.failure(EncryptionFailureException())

        return Result.success(CryptoString.fromBytes("XSALSA20", nonce + ciphertext)!!)
    }

    /**
     * Decrypts the data passed to it.
     *
     * @exception DecryptionFailureException Returned if there was an internal error decrypting the data
     * @exception IllegalArgumentException Returned if there was a key decoding error
     */
    override fun decrypt(encData: CryptoString): Result<ByteArray> {
        val rawKey = key.toRaw()
        val box = SecretBox(rawKey.getOrElse { return it.toFailure() })
        val ciphertext = encData.toRaw().getOrElse { return it.toFailure() }
        val nonce = ciphertext.dropLast(ciphertext.size - SecretBox.nonceLength).toByteArray()

        val decData: ByteArray =
            box.open(ciphertext.drop(SecretBox.nonceLength).toByteArray(), nonce)
                ?: return Result.failure(DecryptionFailureException())
        return Result.success(decData)
    }

    override fun toString(): String {
        return key.toString()
    }

    companion object {

        /**
         * Creates a SecretKey from the specified [CryptoString].
         *
         * @exception UnsupportedAlgorithmException Returned if the library does not support the
         * algorithm specified by the key
         */
        fun from(keyCS: CryptoString): Result<SecretKey> {

            if (!getSupportedSymmetricAlgorithms().contains(keyCS.prefix))
                return Result.failure(UnsupportedAlgorithmException())

            return Result.success(SecretKey(keyCS))
        }

        /**
         * Creates a SecretKey from a string containing data in [CryptoString] format.
         *
         * @exception BadValueException Returned if the key contains invalid data
         * @exception UnsupportedAlgorithmException Returned if the library does not support the
         * algorithm specified by the key string
         */
        fun fromString(keyStr: String): Result<SecretKey> {

            val key = CryptoString.fromString(keyStr) ?: return Result.failure(
                BadValueException("bad key")
            )
            if (!getSupportedSymmetricAlgorithms().contains(key.prefix))
                return Result.failure(UnsupportedAlgorithmException())

            return from(key)

        }

        /**
         * Generates a new symmetric encryption keypair using the specified algorithm.
         *
         * @exception UnsupportedAlgorithmException Returned if the library does not support the
         * algorithm specified
         */
        fun generate(algorithm: String = getPreferredSymmetricAlgorithm()): Result<SecretKey> {

            when (algorithm) {
                "XSALSA20" -> {
                    val rng = SecureRandom()
                    val keyData = ByteArray(SecretBox.keyLength)
                    rng.nextBytes(keyData)

                    return from(CryptoString.fromBytes(algorithm, keyData)!!)
                }
            }

            return Result.failure(UnsupportedAlgorithmException())
        }
    }
}

/** Converts a CryptoString into an [SecretKey] object */
fun CryptoString.toSecretKey(): Result<SecretKey> {
    return SecretKey.from(this)
}
