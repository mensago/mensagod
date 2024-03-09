package keznacl

/**
 * Returns true if the specified algorithm is one supported by the library, regardless of the
 * algorithm's purpose.
 */
fun isSupportedAlgorithm(name: String): Boolean {
    return CryptoType.fromString(name) != null
}

/** Interface for classes which can decrypt data */
interface Decryptor : PrivateKey {
    fun decrypt(encData: CryptoString): Result<ByteArray>

    fun decryptString(encData: CryptoString): Result<String> {
        return decrypt(encData).getOrElse { return it.toFailure() }
            .decodeToString().toSuccess()
    }
}

/** Interface for classes which can encrypt data */
interface Encryptor : PublicKey {
    fun encrypt(data: ByteArray): Result<CryptoString>

    fun encrypt(data: String): Result<CryptoString> {
        return encrypt(data.encodeToByteArray())
    }
}

/** Interface for classes which can verify a cryptographic signature */
interface Verifier : PublicKey {
    fun verify(data: ByteArray, signature: CryptoString): Result<Boolean>
}

/** Interface for classes which can have a method to get the hash of a public key */
interface PublicKey {
    /** Returns the public key as a [CryptoString] */
    fun getPublicKey(): CryptoString

    /** Returns the hash of the public key */
    fun getPublicHash(algorithm: CryptoType = getPreferredHashAlgorithm()): Result<Hash>
}

/**
 * The KeyPair interface brings together functionality which is common to both signing and encryption
 * key pairs.
 */
interface PrivateKey {

    /** Returns the private key as a [CryptoString] */
    fun getPrivateKey(): CryptoString

    /** Returns a [Hash] of the private key using the specified algorithm. */
    fun getPrivateHash(algorithm: CryptoType = getPreferredHashAlgorithm()): Result<Hash>
}

/**
 * The KeyPair interface brings together functionality which is common to both signing and encryption
 * key pairs.
 */
interface KeyPair : PublicKey, PrivateKey