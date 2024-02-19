package keznacl

/**
 * The KeyPair class brings together functionality which is common to both signing and encryption
 * key pairs.
 */
sealed class KeyPair(val publicKey: CryptoString, val privateKey: CryptoString) {

    abstract fun canEncrypt(): Boolean
    abstract fun canSign(): Boolean

    private var publicHash: CryptoString? = null
    private var privateHash: CryptoString? = null

    fun getPublicHash(algorithm: String = getPreferredHashAlgorithm()): Result<CryptoString> {
        if (publicHash == null || publicHash!!.prefix != algorithm)
            publicHash = hash(publicKey.toByteArray(), algorithm).
            getOrElse { return Result.failure(it) }
        return Result.success(publicHash!!)
    }

    fun getPrivateHash(algorithm: String = getPreferredHashAlgorithm()): Result<CryptoString> {
        if (privateHash == null || privateHash!!.prefix != algorithm)
            privateHash = hash(privateKey.toByteArray(), algorithm).
            getOrElse { return Result.failure(it) }
        return Result.success(privateHash!!)
    }
}