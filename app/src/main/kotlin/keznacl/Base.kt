package keznacl

/**
 * Returns true if the specified algorithm is one supported by the library, regardless of the
 * algorithm's purpose.
 */
fun isSupportedAlgorithm(name: String): Boolean {
    return CryptoType.fromString(name) != null
}

/** Interface for classes which can decrypt data */
interface Decryptor {
    fun decrypt(encData: CryptoString): Result<ByteArray>
}

/** Interface for classes which can encrypt data */
interface Encryptor : PublicHasher {
    fun encrypt(data: ByteArray): Result<CryptoString>
}

/** Interface for classes which can verify a cryptographic signature */
interface Verifier : PublicHasher {
    fun verify(data: ByteArray, signature: CryptoString): Result<Boolean>
}

/** Interface for classes which can have a method to get the hash of a public key */
interface PublicHasher {
    fun getPublicHash(algorithm: CryptoType = getPreferredHashAlgorithm()): Result<Hash>
}

/**
 * The KeyPair interface brings together functionality which is common to both signing and encryption
 * key pairs.
 */
interface KeyPair : PublicHasher {

    /** Returns the public key as a [CryptoString] */
    fun getPublicKey(): CryptoString

    /** Returns the private key as a [CryptoString] */
    fun getPrivateKey(): CryptoString

    /** Returns a [Hash] of the private key using the specified algorithm. */
    fun getPrivateHash(algorithm: CryptoType = getPreferredHashAlgorithm()): Result<Hash>
}
