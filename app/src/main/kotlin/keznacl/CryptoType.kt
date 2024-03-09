package keznacl

/**
 * The CryptoType class represents a cryptography algorithm
 */
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
