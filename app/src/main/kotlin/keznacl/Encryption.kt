package keznacl

import com.iwebpp.crypto.TweetNaclFast

/**
 * Returns the asymmetric encryption algorithms supported by the library. Currently the only
 * supported algorithm is Curve25519, which is included in drafts for FIPS 186-5. Other algorithms
 * may be added at a future time.
 */
fun getSupportedAsymmetricAlgorithms(): List<String> {
    return listOf("CURVE25519")
}

/**
 * Returns the recommended asymmetric encryption algorithm supported by the library. If you don't
 * know what to choose for your implementation, this will provide a good default which balances
 * speed and security.
 */
fun getPreferredAsymmetricAlgorithm(): String {
    return "CURVE25519"
}

/**
 * The EncryptionPair class represents a pair of asymmetric encryption keys. It is designed to make
 * managing keys, encrypting/decrypting data, and debugging easier. Usage is pretty simple:
 * getPublicKey(), getPrivateKey(), decrypt(), and encrypt(). Instantiation can be done with from(),
 * fromStrings(), or generate().
 */
class EncryptionPair private constructor(publicKeyStr: CryptoString, privateKeyStr: CryptoString) :
    KeyPair(publicKeyStr, privateKeyStr), Encryptor, Decryptor {

    override fun canEncrypt(): Boolean {
        return true
    }

    override fun canSign(): Boolean {
        return false
    }

    override fun encrypt(data: ByteArray): Result<CryptoString> {
        val rawKey = publicKey.toRaw().getOrElse { return Result.failure(it) }
        val box = SealedBox()
        val result = box.cryptoBoxSeal(data, rawKey)
        if (result.isFailure) {
            return Result.failure(result.exceptionOrNull()!!)
        }

        return Result.success(CryptoString.fromBytes("CURVE25519", result.getOrNull()!!)!!)
    }

    override fun decrypt(encData: CryptoString): Result<ByteArray> {
        val ciphertext = encData.toRaw().getOrElse { return Result.failure(it) }
        val box = SealedBox()
        return box.cryptoBoxSealOpen(ciphertext,
            publicKey.toRaw().getOrElse { return Result.failure(it) },
            privateKey.toRaw().getOrElse { return Result.failure(it) })
    }

    override fun toString(): String {
        return "$publicKey,$privateKey"
    }

    companion object {

        fun from(pubKeyCS: CryptoString, privKeyCS: CryptoString): Result<EncryptionPair> {

            if (pubKeyCS.prefix != privKeyCS.prefix)
                return Result.failure(KeyErrorException())
            if (!getSupportedAsymmetricAlgorithms().contains(pubKeyCS.prefix))
                return Result.failure(UnsupportedAlgorithmException())

            return Result.success(EncryptionPair(pubKeyCS, privKeyCS))
        }

        fun fromStrings(pubKeyStr: String, privKeyStr: String): Result<EncryptionPair> {

            val pubKey = CryptoString.fromString(pubKeyStr) ?: return Result.failure(
                BadValueException("bad public key")
            )
            val privKey = CryptoString.fromString(privKeyStr) ?: return Result.failure(
                BadValueException("bad private key")
            )
            return from(pubKey, privKey)
        }

        fun generate(algorithm: String = getPreferredAsymmetricAlgorithm()):
                Result<EncryptionPair> {

            if (!getSupportedAsymmetricAlgorithms().contains(algorithm))
                return Result.failure(UnsupportedAlgorithmException())

            when (algorithm) {
                "CURVE25519" -> {
                    val keyPair = TweetNaclFast.Box.keyPair()
                    val pubKey = CryptoString.fromBytes("CURVE25519", keyPair.publicKey)
                        ?: return Result.failure(KeyErrorException())

                    val privKey = CryptoString.fromBytes("CURVE25519", keyPair.secretKey)
                        ?: return Result.failure(KeyErrorException())

                    return from(pubKey, privKey)
                }
            }

            return Result.failure(UnsupportedAlgorithmException())
        }

    }
}

/** The EncryptionKey class represents just a person's encryption key. */
class EncryptionKey private constructor() : Encryptor {
    var publicKey: CryptoString? = null
        private set

    private var publicHash: CryptoString? = null

    val key: CryptoString
        get() {
            return publicKey!!
        }

    override fun encrypt(data: ByteArray): Result<CryptoString> {
        val rawKey = publicKey!!.toRaw()
        val box = SealedBox()
        val result = box.cryptoBoxSeal(data, rawKey.getOrElse { return Result.failure(it) })
        if (result.isFailure) {
            return Result.failure(result.exceptionOrNull()!!)
        }

        return Result.success(CryptoString.fromBytes("CURVE25519", result.getOrNull()!!)!!)
    }

    override fun getPublicHash(algorithm: String): Result<CryptoString> {
        if (publicHash == null || publicHash!!.prefix != algorithm)
            publicHash =
                hash(publicKey!!.toByteArray(), algorithm).getOrElse { return Result.failure(it) }
        return Result.success(publicHash!!)
    }

    override fun toString(): String {
        return publicKey.toString()
    }

    companion object {

        fun from(pubKey: CryptoString): Result<EncryptionKey> {

            if (!getSupportedAsymmetricAlgorithms().contains(pubKey.prefix))
                return Result.failure(UnsupportedAlgorithmException())

            return Result.success(EncryptionKey().also { it.publicKey = pubKey })
        }

        fun fromString(pubKeyStr: String): Result<EncryptionKey> {

            val pubKey = CryptoString.fromString(pubKeyStr) ?: return Result.failure(
                BadValueException("bad public key")
            )
            return from(pubKey)
        }
    }
}

/** Converts a CryptoString into an EncryptionKey object */
fun CryptoString.toEncryptionKey(): Result<EncryptionKey> {
    return EncryptionKey.from(this)
}
