package keznacl

import com.iwebpp.crypto.TweetNaclFast
import kotlinx.serialization.Serializable

/** Returns true if the string represents a supported asymmetric encryption algorithm */
fun isSupportedAsymmetric(s: String): Boolean {
    return s.uppercase() == "CURVE25519"
}

/**
 * Returns the asymmetric encryption algorithms supported by the library. Currently the only
 * supported algorithm is CURVE25519, which is included in drafts for FIPS 186-5. Other algorithms
 * may be added at a future time.
 */
fun getSupportedAsymmetricAlgorithms(): List<CryptoType> {
    return listOf(CryptoType.CURVE25519)
}

/**
 * Returns the recommended asymmetric encryption algorithm supported by the library. If you don't
 * know what to choose for your implementation, this will provide a good default which balances
 * speed and security.
 */
fun getPreferredAsymmetricAlgorithm(): CryptoType {
    return CryptoType.CURVE25519
}

/**
 * The EncryptionPair class represents a pair of asymmetric encryption keys. It is designed to make
 * managing keys, encrypting/decrypting data, and debugging easier. Usage is pretty simple:
 * getPublicKey(), getPrivateKey(), decrypt(), and encrypt(). Instantiation can be done with from(),
 * fromStrings(), or generate().
 */
@Serializable
class EncryptionPair private constructor(
    val pubKey: CryptoString,
    val privKey: CryptoString
) : Encryptor, Decryptor, KeyPair {

    override fun getPublicKey(): CryptoString {
        return pubKey
    }

    override fun getPrivateKey(): CryptoString {
        return privKey
    }

    override fun getPublicHash(algorithm: CryptoType): Result<Hash> {
        return pubKey.hash(algorithm)
    }

    override fun getPrivateHash(algorithm: CryptoType): Result<Hash> {
        return privKey.hash(algorithm)
    }

    /**
     * Encrypts the passed data into a [CryptoString].
     *
     * @exception IllegalArgumentException Returned if there was a decoding error
     */
    override fun encrypt(data: ByteArray): Result<CryptoString> {
        val rawKey = pubKey.toRaw().getOrElse { return it.toFailure() }
        val box = SealedBox()
        val result = box.cryptoBoxSeal(data, rawKey).getOrElse { return it.toFailure() }

        return CryptoString.fromBytes(CryptoType.CURVE25519, result)!!.toSuccess()
    }

    /**
     * Decrypts the data passed into a [ByteArray].
     *
     * @exception IllegalArgumentException Returned if there was a decoding error
     */
    override fun decrypt(encData: CryptoString): Result<ByteArray> {
        val ciphertext = encData.toRaw().getOrElse { return it.toFailure() }
        val box = SealedBox()
        return box.cryptoBoxSealOpen(ciphertext,
            pubKey.toRaw().getOrElse { return it.toFailure() },
            privKey.toRaw().getOrElse { return it.toFailure() })
    }

    override fun toString(): String {
        return "$pubKey,$privKey"
    }

    companion object {

        /**
         * Creates an EncryptionPair from the specified CryptoString objects.
         *
         * @exception KeyErrorException Returned if given keys using different algorithms
         * @exception UnsupportedAlgorithmException Returned if the library does not support the
         * algorithm specified by the keys
         */
        fun from(pubKeyCS: CryptoString, privKeyCS: CryptoString): Result<EncryptionPair> {

            if (pubKeyCS.prefix != privKeyCS.prefix)
                return KeyErrorException().toFailure()
            if (!isSupportedAsymmetric(pubKeyCS.prefix))
                return UnsupportedAlgorithmException().toFailure()

            return EncryptionPair(pubKeyCS, privKeyCS).toSuccess()
        }

        /**
         * Creates an EncryptionPair from two strings containing data in [CryptoString] format.
         *
         * @exception BadValueException Returned if either key contains invalid data
         * @exception KeyErrorException Returned if given keys using different algorithms
         * @exception UnsupportedAlgorithmException Returned if the library does not support the
         * algorithm specified by the keys
         */
        fun fromStrings(pubKeyStr: String, privKeyStr: String): Result<EncryptionPair> {
            val pubKey = CryptoString.fromString(pubKeyStr)
                ?: return BadValueException("bad public key").toFailure()
            val privKey = CryptoString.fromString(privKeyStr)
                ?: return BadValueException("bad private key").toFailure()
            return from(pubKey, privKey)
        }

        /**
         * Generates a new asymmetric encryption keypair using the specified algorithm.
         *
         * @exception KeyErrorException Returned if there was a problem generating the keypair
         * @exception UnsupportedAlgorithmException Returned if the library does not support the
         * algorithm specified
         */
        fun generate(algorithm: CryptoType = getPreferredAsymmetricAlgorithm()):
                Result<EncryptionPair> {

            when (algorithm) {
                CryptoType.CURVE25519 -> {
                    val keyPair = TweetNaclFast.Box.keyPair()
                    val pubKey = CryptoString.fromBytes(CryptoType.CURVE25519, keyPair.publicKey)
                        ?: return KeyErrorException().toFailure()

                    val privKey = CryptoString.fromBytes(CryptoType.CURVE25519, keyPair.secretKey)
                        ?: return KeyErrorException().toFailure()

                    return from(pubKey, privKey)
                }

                else -> return UnsupportedAlgorithmException().toFailure()
            }
        }

    }
}

/**
 * The EncryptionKey class represents just an encryption key without its corresponding
 * decryption key.
 */
class EncryptionKey private constructor(val key: CryptoString) : Encryptor {

    private var publicHash: Hash? = null

    /**
     * Encrypts the passed data and returns the encrypted data encoded as a [CryptoString].
     *
     * @exception IllegalArgumentException Returned if there was a decoding error
     */
    override fun encrypt(data: ByteArray): Result<CryptoString> {
        val rawKey = key.toRaw().getOrElse { return it.toFailure() }
        val encrypted = SealedBox().cryptoBoxSeal(data, rawKey)
            .getOrElse { return it.toFailure() }

        return CryptoString.fromBytes(CryptoType.CURVE25519, encrypted)!!.toSuccess()
    }

    /** Interface override inherited from [PublicKey] */
    override fun getPublicKey(): CryptoString {
        return key
    }

    /** Interface override inherited from [PublicKey] */
    override fun getPublicHash(algorithm: CryptoType): Result<Hash> {
        if (publicHash == null || publicHash!!.prefix != algorithm.toString())
            publicHash = hash(key.toByteArray(), algorithm).getOrElse { return it.toFailure() }
        return publicHash!!.toSuccess()
    }

    override fun toString(): String {
        return key.toString()
    }

    companion object {

        /**
         * Creates an EncryptionKey from the specified [CryptoString].
         *
         * @exception UnsupportedAlgorithmException Returned if the library does not support the
         * algorithm specified by the key
         */
        fun from(pubKey: CryptoString): Result<EncryptionKey> {

            if (!isSupportedAsymmetric(pubKey.prefix))
                return UnsupportedAlgorithmException().toFailure()

            return EncryptionKey(pubKey).toSuccess()
        }

        /**
         * Creates an EncryptionPair from two strings containing data in [CryptoString] format.
         *
         * @exception BadValueException Returned if either key contains invalid data
         * @exception UnsupportedAlgorithmException Returned if the library does not support the
         * algorithm specified by the key string
         */
        fun fromString(s: String): Result<EncryptionKey> {

            val pubKey = CryptoString.fromString(s)
                ?: return BadValueException("bad public key").toFailure()

            return from(pubKey)
        }
    }
}

/**
 * Converts a CryptoString into an [EncryptionKey] object
 *
 * @exception UnsupportedAlgorithmException Returned if the library does not support the
 * algorithm specified by the key
 */
fun CryptoString.toEncryptionKey(): Result<EncryptionKey> {
    return EncryptionKey.from(this)
}
