package keznacl

import com.iwebpp.crypto.TweetNaclFast.SecretBox
import java.security.SecureRandom

/**
 * Returns the symmetric encryption algorithms supported by the library. Currently the only supported algorithm is
 * XSalsa20. Other algorithms may be added at a future time.
 */
fun getSupportedSymmetricAlgorithms(): List<String> {
    return listOf("XSALSA20")
}

/**
 * Returns the recommended secret key encryption algorithm supported by the library. If you don't know what to choose
 * for your implementation, this will provide a good default which balances speed and security.
 */
fun getPreferredSymmetricAlgorithm(): String {
    return "XSALSA20"
}


class SecretKey private constructor(keyStr: CryptoString) : Encryptor, Decryptor {
    val key: CryptoString = keyStr
    private var keyHash: CryptoString? = null

    fun getHash(algorithm: String = getPreferredHashAlgorithm()): Result<CryptoString> {
        if (keyHash == null || keyHash!!.prefix != algorithm)
            keyHash = hash(key.toByteArray(), algorithm).getOrElse { return Result.failure(it) }
        return Result.success(keyHash!!)
    }

    override fun getPublicHash(algorithm: String): Result<CryptoString> {
        return getHash(algorithm)
    }

    override fun encrypt(data: ByteArray): Result<CryptoString> {
        val rawKey = key.toRaw()
        val box = SecretBox(rawKey.getOrElse { return Result.failure(it) })

        val rng = SecureRandom()
        val nonce = ByteArray(SecretBox.nonceLength)
        rng.nextBytes(nonce)

        val ciphertext: ByteArray =
            box.box(data, nonce) ?: return Result.failure(EncryptionFailureException())

        return Result.success(CryptoString.fromBytes("XSALSA20", nonce + ciphertext)!!)
    }

    override fun decrypt(encData: CryptoString): Result<ByteArray> {
        val rawKey = key.toRaw()
        val box = SecretBox(rawKey.getOrElse { return Result.failure(it) })
        val ciphertext = encData.toRaw().getOrElse { return Result.failure(it) }
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

        fun from(keyCS: CryptoString): Result<SecretKey> {

            if (!getSupportedSymmetricAlgorithms().contains(keyCS.prefix))
                return Result.failure(UnsupportedAlgorithmException())

            return Result.success(SecretKey(keyCS))
        }

        fun fromString(pubKeyStr: String): Result<SecretKey> {

            val pubKey = CryptoString.fromString(pubKeyStr) ?: return Result.failure(
                BadValueException("bad key")
            )
            return from(pubKey)

        }

        fun generate(algorithm: String = getPreferredSymmetricAlgorithm()): Result<SecretKey> {
            if (!getSupportedSymmetricAlgorithms().contains(algorithm))
                return Result.failure(UnsupportedAlgorithmException())

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

/** Converts a CryptoString into an SecretKey object */
fun CryptoString.toSecretKey(): Result<SecretKey> {
    return SecretKey.from(this)
}
