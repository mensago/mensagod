package keznacl

/**
 * The KeyPair class brings together functionality which is common to both signing and encryption
 * key pairs.
 */
sealed class KeyPair(val publicKey: CryptoString, val privateKey: CryptoString) {

    /** Returns true if the KeyPair instance is able to encrypt data */
    abstract fun canEncrypt(): Boolean

    /** Returns true if the KeyPair instance is able to sign data */
    abstract fun canSign(): Boolean

    private var publicHash: Hash? = null
    private var privateHash: Hash? = null

    /** Returns a [Hash] of the public key using the specified algorithm. */
    fun getPublicHash(algorithm: String = getPreferredHashAlgorithm()): Result<Hash> {
        if (publicHash == null || publicHash!!.prefix != algorithm)
            publicHash =
                hash(publicKey.toByteArray(), algorithm).getOrElse { return it.toFailure() }
        return Result.success(publicHash!!)
    }

    /** Returns a [Hash] of the private key using the specified algorithm. */
    fun getPrivateHash(algorithm: String = getPreferredHashAlgorithm()): Result<Hash> {
        if (privateHash == null || privateHash!!.prefix != algorithm)
            privateHash =
                hash(privateKey.toByteArray(), algorithm).getOrElse { return it.toFailure() }
        return Result.success(privateHash!!)
    }
}
