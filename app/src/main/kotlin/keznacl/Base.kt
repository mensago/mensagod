package keznacl

/**
 * Returns true if the specified algorithm is one supported by the library, regardless of the
 * algorithm's purpose.
 */
fun isSupportedAlgorithm(name: String): Boolean {
    return when (name) {
        "CURVE25519", "ED25519", "XSALSA20", "BLAKE2B-256" -> true
        else -> false
    }
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
    fun getPublicHash(algorithm: String = getPreferredHashAlgorithm()): Result<Hash>
}
