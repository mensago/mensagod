package keznacl

import kotlinx.serialization.Serializable

/**
 * The CryptoType class represents a cryptography algorithm supported by the library.
 */
@Serializable
enum class CryptoType {

    // Asymmetric Encryption
    CURVE25519,

    // Symmetric Encryption
    XSALSA20,

    // Digital Signatures
    ED25519,

    // Hash Algorithms
    BLAKE2B_256,
    SHA_256;

    /* Returns true if the object represents a supported asymmetric encryption algorithm */
    fun isAsymmetric(): Boolean {
        return when (this) {
            CURVE25519 -> true
            else -> false
        }
    }

    /* Returns true if the object represents a supported digital signing algorithm */
    fun isSigning(): Boolean {
        return when (this) {
            ED25519 -> true
            else -> false
        }
    }

    /* Returns true if the object represents a supported symmetric encryption algorithm */
    fun isSymmetric(): Boolean {
        return when (this) {
            XSALSA20 -> true
            else -> false
        }
    }

    /* Returns true if the object represents a supported hashing algorithm */
    fun isHash(): Boolean {
        return when (this) {
            BLAKE2B_256, SHA_256 -> true
            else -> false
        }
    }


    override fun toString(): String {
        return when (this) {
            CURVE25519 -> "CURVE25519"

            XSALSA20 -> "XSALSA20"

            ED25519 -> "ED25519"

            BLAKE2B_256 -> "BLAKE2B-256"
            SHA_256 -> "SHA-256"
        }
    }

    companion object {

        fun fromString(s: String): CryptoType? {
            return when (s.uppercase()) {
                "CURVE25519" -> CURVE25519

                "XSALSA20" -> XSALSA20

                "ED25519" -> ED25519

                "BLAKE2B-256" -> BLAKE2B_256
                "SHA-256" -> SHA_256
                else -> null
            }
        }

        /** Returns true if the specified algorithm is supported by the library */
        fun isSupported(s: String): Boolean {
            return fromString(s) != null
        }
    }
}

fun CryptoString.getType(): CryptoType? {
    return CryptoType.fromString(prefix)
}

fun EncryptionPair.getType(): CryptoType? {
    return CryptoType.fromString(pubKey.prefix)
}

fun EncryptionKey.getType(): CryptoType? {
    return CryptoType.fromString(key.prefix)
}

fun SigningPair.getType(): CryptoType? {
    return CryptoType.fromString(pubKey.prefix)
}

fun VerificationKey.getType(): CryptoType? {
    return CryptoType.fromString(key.prefix)
}

fun SecretKey.getType(): CryptoType? {
    return CryptoType.fromString(key.prefix)
}

