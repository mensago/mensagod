package keznacl

import com.iwebpp.crypto.TweetNaclFast.Signature
import kotlinx.serialization.Serializable

/** Returns true if the string represents a supported digital signing algorithm */
fun isSupportedSigning(s: String): Boolean {
    return s.uppercase() == "ED25519"
}

/**
 * Returns the digital signing algorithms supported by the library. Currently the only supported
 * algorithm is ED25519. Other algorithms may be added at a future time.
 */
fun getSupportedSigningAlgorithms(): List<CryptoType> {
    return listOf(CryptoType.ED25519)
}

/**
 * Returns the recommended digital signature algorithm supported by the library. If you don't know
 * what to choose for your implementation, this will provide a good default which balances speed and
 * security.
 */
fun getPreferredSigningAlgorithm(): CryptoType {
    return CryptoType.ED25519
}

/**
 * The SigningPair class represents a cryptographic keypair used for creating and verifying digital
 * signatures.
 */
@Serializable
class SigningPair private constructor(val pubKey: CryptoString, val privKey: CryptoString) :
    Verifier, KeyPair {

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
     * Creates a digital signature of the data supplied to it.
     *
     * @exception IllegalArgumentException Returned if there was a Base85 decoding error
     * @exception SigningFailureException Returned if there was an error signing the data
     */
    fun sign(data: ByteArray): Result<CryptoString> {
        if (data.isEmpty()) return Result.failure(EmptyDataException())

        // TweetNaCl expects the private key to be 64-bytes -- the first 32 are the private key and
        // the last are the public key. We don't do that here -- they are split because they are
        // associated a different way.
        val rawKey = Base85.decode(privKey.encodedData + pubKey.encodedData)
            .getOrElse { return it.toFailure() }
        val box = Signature(null, rawKey)
        val signature = box.detached(data)

        if (signature == null || signature.isEmpty())
            return Result.failure(SigningFailureException())

        return Result.success(CryptoString.fromBytes(CryptoType.ED25519, signature)!!)
    }

    override fun toString(): String {
        return "$pubKey,$privKey"
    }

    /**
     * Verifies the given signature for the data passed and returns true if it verifies and false if
     * it does not.
     *
     * @exception AlgorithmMismatchException Returned if the signature algorithm does not match that
     * of the SigningPair object.
     */
    override fun verify(data: ByteArray, signature: CryptoString): Result<Boolean> {
        if (data.isEmpty()) return Result.failure(EmptyDataException())
        if (signature.prefix != pubKey.prefix) return Result.failure(AlgorithmMismatchException())

        val rawPubKey = pubKey.toRaw().getOrElse { return it.toFailure() }
        val rawSignature = signature.toRaw().getOrElse { return it.toFailure() }
        val box = Signature(rawPubKey, null)

        return Result.success(box.detached_verify(data, rawSignature))
    }

    companion object {

        /**
         * Creates a SigningPair from the specified CryptoStrings.
         *
         * @exception KeyErrorException Returned if given keys using different algorithms
         * @exception UnsupportedAlgorithmException Returned if the library does not support the
         * algorithm specified by the keys
         */
        fun from(pubKeyStr: CryptoString, privKeyStr: CryptoString): Result<SigningPair> {

            if (pubKeyStr.prefix != privKeyStr.prefix)
                return Result.failure(KeyErrorException())
            if (!isSupportedSigning(pubKeyStr.prefix))
                return Result.failure(UnsupportedAlgorithmException())

            return Result.success(SigningPair(pubKeyStr, privKeyStr))
        }

        /**
         * Creates a SigningPair from two strings containing data in [CryptoString] format.
         *
         * @exception BadValueException Returned if either key contains invalid data
         * @exception KeyErrorException Returned if given keys using different algorithms
         * @exception UnsupportedAlgorithmException Returned if the library does not support the
         * algorithm specified by the keys
         */
        fun fromStrings(pubKeyStr: String, privKeyStr: String): Result<SigningPair> {

            val publicKeyCS = CryptoString.fromString(pubKeyStr) ?: return Result.failure(
                BadValueException("bad public key")
            )
            val privateKeyCS = CryptoString.fromString(privKeyStr) ?: return Result.failure(
                BadValueException("bad private key")
            )
            return from(publicKeyCS, privateKeyCS)
        }

        /**
         * Generates a new signing keypair using the specified algorithm.
         *
         * @exception KeyErrorException Returned if there was a problem generating the keypair
         * @exception UnsupportedAlgorithmException Returned if the library does not support the
         * algorithm specified
         */
        fun generate(algorithm: CryptoType = getPreferredSigningAlgorithm()): Result<SigningPair> {

            when (algorithm) {
                CryptoType.ED25519 -> {
                    val keyPair = Signature.keyPair()
                    val publicKeyCS = CryptoString.fromBytes(CryptoType.ED25519, keyPair.publicKey)
                        ?: return Result.failure(KeyErrorException())

                    val privateKeyCS =
                        CryptoString.fromBytes(
                            CryptoType.ED25519,
                            keyPair.secretKey.copyOfRange(0, 32)
                        ) ?: return Result.failure(KeyErrorException())
                    return from(publicKeyCS, privateKeyCS)
                }

                else -> return Result.failure(UnsupportedAlgorithmException())
            }
        }
    }
}

/** The VerificationKey class is the public half of a signing keypair. */
@Serializable
class VerificationKey : Verifier {

    var publicKey: CryptoString? = null
        private set

    private var publicHash: Hash? = null

    val key: CryptoString
        get() {
            return publicKey!!
        }

    /**
     * Verifies the given signature for the data passed and returns true if it verifies and false if
     * it does not.
     *
     * @exception AlgorithmMismatchException Returned if the signature algorithm does not match that
     * of the SigningPair object.
     */
    override fun verify(data: ByteArray, signature: CryptoString): Result<Boolean> {
        if (data.isEmpty()) return Result.failure(EmptyDataException())
        if (signature.prefix != key.prefix) return Result.failure(AlgorithmMismatchException())

        val rawKey = key.toRaw().getOrElse { return it.toFailure() }
        val box = Signature(rawKey, null)

        return Result.success(
            box.detached_verify(data, signature.toRaw().getOrElse { return it.toFailure() })
        )
    }

    /**
     * Required function for the Verifier interface which returns a hash of the verification key.
     *
     * @exception UnsupportedAlgorithmException Returned if the library does not support the
     * algorithm specified by the keys
     */
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
         * Creates a VerificationKey from the specified [CryptoString].
         *
         * @exception UnsupportedAlgorithmException Returned if the library does not support the
         * algorithm specified by the key
         */
        fun from(key: CryptoString): Result<VerificationKey> {

            if (!isSupportedSigning(key.prefix))
                return Result.failure(UnsupportedAlgorithmException())

            return Result.success(VerificationKey().also {
                it.publicKey = key
            })
        }

        /**
         * Creates a Verification from a string containing data in [CryptoString] format.
         *
         * @exception BadValueException Returned if the key contains invalid data
         * @exception UnsupportedAlgorithmException Returned if the library does not support the
         * algorithm specified by the key string
         */
        fun fromString(pubKeyStr: String): Result<VerificationKey> {

            val publicKeyCS =
                CryptoString.fromString(pubKeyStr)
                    ?: return Result.failure(BadValueException("bad public key"))
            return from(publicKeyCS)
        }
    }
}

/** Converts a CryptoString into a [VerificationKey] object */
fun CryptoString.toVerificationKey(): Result<VerificationKey> {
    return VerificationKey.from(this)
}
