package keznacl

import com.iwebpp.crypto.TweetNaclFast
import kotlinx.serialization.Serializable

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
        val result = box.cryptoBoxSeal(data, rawKey)
        if (result.isFailure) {
            return Result.failure(result.exceptionOrNull()!!)
        }

        return Result.success(CryptoString.fromBytes(CryptoType.CURVE25519, result.getOrNull()!!)!!)
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
                return Result.failure(KeyErrorException())
            if (!isSupportedAsymmetric(pubKeyCS.prefix))
                return Result.failure(UnsupportedAlgorithmException())

            return Result.success(EncryptionPair(pubKeyCS, privKeyCS))
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

            val pubKey = CryptoString.fromString(pubKeyStr) ?: return Result.failure(
                BadValueException("bad public key")
            )
            val privKey = CryptoString.fromString(privKeyStr) ?: return Result.failure(
                BadValueException("bad private key")
            )
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
                        ?: return Result.failure(KeyErrorException())

                    val privKey = CryptoString.fromBytes(CryptoType.CURVE25519, keyPair.secretKey)
                        ?: return Result.failure(KeyErrorException())

                    return from(pubKey, privKey)
                }

                else -> return Result.failure(UnsupportedAlgorithmException())
            }
        }

    }
}

/**
 * The EncryptionKey class represents just an encryption key without its corresponding
 * decryption key.
 */
class EncryptionKey private constructor() : Encryptor {
    var publicKey: CryptoString? = null
        private set

    private var publicHash: Hash? = null

    /**
     * The textual representation of the encryption key in CryptoString format
     */
    val key: CryptoString
        get() {
            return publicKey!!
        }

    /**
     * Encrypts the passed data and returns the encrypted data encoded as a [CryptoString].
     *
     * @exception IllegalArgumentException Returned if there was a decoding error
     */
    override fun encrypt(data: ByteArray): Result<CryptoString> {
        val rawKey = publicKey!!.toRaw()
        val box = SealedBox()
        val result = box.cryptoBoxSeal(data, rawKey.getOrElse { return it.toFailure() })
        if (result.isFailure) {
            return Result.failure(result.exceptionOrNull()!!)
        }

        return Result.success(CryptoString.fromBytes(CryptoType.CURVE25519, result.getOrNull()!!)!!)
    }

    /** Interface override inherited from [PublicHasher] */
    override fun getPublicHash(algorithm: CryptoType): Result<Hash> {
        if (publicHash == null || publicHash!!.prefix != algorithm.toString())
            publicHash =
                hash(publicKey!!.toByteArray(), algorithm).getOrElse { return it.toFailure() }
        return Result.success(publicHash!!)
    }

    override fun toString(): String {
        return publicKey.toString()
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
                return Result.failure(UnsupportedAlgorithmException())

            return Result.success(EncryptionKey().also { it.publicKey = pubKey })
        }

        /**
         * Creates an EncryptionPair from two strings containing data in [CryptoString] format.
         *
         * @exception BadValueException Returned if either key contains invalid data
         * @exception UnsupportedAlgorithmException Returned if the library does not support the
         * algorithm specified by the key string
         */
        fun fromString(pubKeyStr: String): Result<EncryptionKey> {

            val pubKey = CryptoString.fromString(pubKeyStr) ?: return Result.failure(
                BadValueException("bad public key")
            )
            if (!isSupportedAsymmetric(pubKey.prefix))
                return Result.failure(UnsupportedAlgorithmException())

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
