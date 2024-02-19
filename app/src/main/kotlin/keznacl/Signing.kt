package keznacl

import com.iwebpp.crypto.TweetNaclFast.Signature

/**
 * Returns the digital signing algorithms supported by the library. Currently the only supported algorithm is
 * Ed25519. Other algorithms may be added at a future time.
 */
fun getSupportedSigningAlgorithms(): List<String> {
    return listOf("ED25519")
}

/**
 * Returns the recommended digital signature algorithm supported by the library. If you don't know what to choose
 * for your implementation, this will provide a good default which balances speed and security.
 */
fun getPreferredSigningAlgorithm(): String { return "ED25519" }

class SigningPair private constructor(publicKeyStr: CryptoString, privateKeyStr: CryptoString):
    KeyPair(publicKeyStr, privateKeyStr), Verifier {

    override fun canEncrypt(): Boolean { return false }
    override fun canSign(): Boolean { return true }

    /**
     * Creates a digital signature of the data supplied to it.
     *
     * @throws IllegalArgumentException Returned if there was a Base85 decoding error
     * @throws SigningFailureException Returned if there was an error signing the data
     */
    fun sign(data: ByteArray): Result<CryptoString> {
        if (data.isEmpty()) return Result.failure(EmptyDataException())

        // TweetNaCl expects the private key to be 64-bytes -- the first 32 are the private key and
        // the last are the public key. We don't do that here -- they are split because they are
        // associated a different way.
        val rawKey = Base85.rfc1924Decoder
            .decode(privateKey.encodedData + publicKey.encodedData)
            .getOrElse { return Result.failure(it) }
        val box = Signature(null, rawKey)
        val signature = box.detached(data)

        if (signature == null || signature.isEmpty())
            return Result.failure(SigningFailureException())

        return Result.success(CryptoString.fromBytes("ED25519", signature)!!)
    }

    override fun toString(): String { return "$publicKey,$privateKey" }

    override fun verify(data: ByteArray, signature: CryptoString): Result<Boolean> {
        if (data.isEmpty()) return Result.failure(EmptyDataException())
        if (signature.prefix != publicKey.prefix) return Result.failure(AlgorithmMismatchException())

        val rawPubKey = publicKey.toRaw().getOrElse { return Result.failure(it) }
        val rawSignature = signature.toRaw().getOrElse { return Result.failure(it) }
        val box = Signature(rawPubKey, null)

        return Result.success(box.detached_verify(data, rawSignature))
    }

    companion object {

        fun from(pubKeyStr: CryptoString, privKeyStr: CryptoString): Result<SigningPair> {

            if (pubKeyStr.prefix != privKeyStr.prefix)
                return Result.failure(KeyErrorException())
            if (!getSupportedSigningAlgorithms().contains(pubKeyStr.prefix))
                return Result.failure(UnsupportedAlgorithmException())

            return Result.success(SigningPair(pubKeyStr, privKeyStr))
        }

        fun fromStrings(pubKeyStr: String, privKeyStr: String): Result<SigningPair> {

            val publicKeyCS = CryptoString.fromString(pubKeyStr) ?:
                return Result.failure(BadValueException("bad public key"))
            val privateKeyCS = CryptoString.fromString(privKeyStr) ?:
                return Result.failure(BadValueException("bad private key"))
            return from(publicKeyCS, privateKeyCS)
        }

        fun generate(algorithm: String = getPreferredSigningAlgorithm()): Result<SigningPair> {
            if (!getSupportedSigningAlgorithms().contains(algorithm))
                return Result.failure(UnsupportedAlgorithmException())

            when (algorithm) {
                "ED25519" -> {
                    val keyPair = Signature.keyPair()
                    val publicKeyCS = CryptoString.fromBytes("ED25519", keyPair.publicKey) ?:
                    return Result.failure(KeyErrorException())

                    val privateKeyCS =
                        CryptoString.fromBytes("ED25519", keyPair.secretKey.copyOfRange(0,32)) ?:
                        return Result.failure(KeyErrorException())
                    return from(publicKeyCS, privateKeyCS)
                }
            }

            return Result.failure(UnsupportedAlgorithmException())
        }
    }
}

class VerificationKey: Verifier, PublicHasher {
    var publicKey: CryptoString? = null
        private set

    private var publicHash: CryptoString? = null

    val key: CryptoString
        get() { return publicKey!! }

    override fun verify(data: ByteArray, signature: CryptoString): Result<Boolean> {
        if (data.isEmpty()) return Result.failure(EmptyDataException())
        if (signature.prefix != key.prefix) return Result.failure(AlgorithmMismatchException())

        val rawKey = key.toRaw().getOrElse { return Result.failure(it) }
        val box = Signature(rawKey, null)

        return Result.success(box.detached_verify(data, signature.toRaw().
            getOrElse { return Result.failure(it) }))
    }

    override fun getPublicHash(algorithm: String): Result<CryptoString> {
        if (publicHash == null || publicHash!!.prefix != algorithm)
            publicHash = hash(publicKey!!.toByteArray(), algorithm).
            getOrElse { return Result.failure(it) }
        return Result.success(publicHash!!)
    }

    override fun toString(): String { return publicKey.toString() }

    companion object {

        fun from(pubKey: CryptoString): Result<VerificationKey> {

            if (!isSupportedAlgorithm(pubKey.prefix)) return Result.failure(UnsupportedAlgorithmException())

            return Result.success(VerificationKey().also {
                it.publicKey = pubKey
            })
        }

        fun fromString(pubKeyStr: String): Result<VerificationKey> {

            val publicKeyCS =
                CryptoString.fromString(pubKeyStr) ?: return Result.failure(BadValueException("bad public key"))
            return from(publicKeyCS)
        }
    }
}

/** Converts a CryptoString into an VerificationKey object */
fun CryptoString.toVerificationKey(): Result<VerificationKey> {
    return VerificationKey.from(this)
}
