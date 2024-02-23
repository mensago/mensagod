package keznacl

import kotlinx.serialization.Serializable
import java.util.regex.Pattern

/**
 * # CryptoString
 *
 * One of the many challenges with working with encryption is that keys and hashes are
 * arbitrary-looking binary blobs of data -- they have zero meaning to people just looking at them.
 * They also lack context or any other descriptive information; a 256-bit BLAKE2B hash looks the
 * same as a SHA256 hash, but Heaven help you if you get something mixed up.
 *
 * The solution is to represent keys and hashes as text and pair an algorithm nametag with the text
 * representation of the key or hash. For example, a sample 128-bit BLAKE2B hash in its binary form
 * is represented in hex as `a6 30 2a b0 da ef 14 fb 9b 82 b9 69 3e 78 76 6b`. Without spaces, this
 * is 32 characters. The same hash can be represented in CryptoString format as
 * `BLAKE2B-128:rZ6h7+V2$mn}WG%K6rL(`.
 *
 * The format consists of the prefix, a colon for the separator, and the Base85-encoded binary data.
 * Base85 was chosen because of its higher efficiency and source code compatibility. The prefix
 * consists of up to 24 characters, which may be capital ASCII letters, numbers, or dashes. A colon
 * is used to separate the prefix from the encoded data.
 *
 * The official prefixes as of this writing are:
 *
 * - ED25519
 * - CURVE25519
 * - AES-128 / AES-256 / AES-384 / AES-512
 * - SALSA20 / XSALSA20
 * - SHA-256 / SHA-384 / SHA-512
 * - SHA3-256 / SHA3-384 / SHA3-512
 * - BLAKE2B-256 / BLAKE2B-512
 * - BLAKE3-256
 * - K12-256
 *
 * Regular usage of a CryptoString mostly involves creating an instance from other data. The
 * constructor can take a CryptoString-formatted string or a string prefix and some raw bytes. Once
 * data has been put into the instance, getting it back out is just a matter of casting to a string,
 * or calling `to_string()`, `to_bytes()`, or `to_raw()`. The last of these three methods only
 * returns the raw data stored in the object.
 */
@Serializable
open class CryptoString protected constructor(val prefix: String, val encodedData: String) {
    var value: String = ""
        private set
        get() {
            return "$prefix:$encodedData"
        }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as CryptoString
        if (prefix != other.prefix) return false
        return encodedData == other.encodedData
    }

    override fun hashCode(): Int {
        return value.hashCode()
    }

    override fun toString(): String {
        return value
    }

    fun toByteArray(): ByteArray {
        return value.toByteArray()
    }

    /**
     * Returns the object's raw, unencoded data
     *
     * @throws IllegalArgumentException Returned if there was a Base85 decoding error
     */
    fun toRaw(): Result<ByteArray> {
        val out = Base85.rfc1924Decoder.decode(encodedData).getOrElse { return Result.failure(it) }
        return Result.success(out)
    }

    /** Calculates and returns the hash of the string value of the instance */
    fun calcHash(algorithm: String? = null): Result<CryptoString> {
        return hash(value.encodeToByteArray(), algorithm)
    }

    companion object {
        private val csPattern = Pattern.compile(
            "^([A-Z0-9-]{1,24}):([0-9A-Za-z!#\$%&()*+-;<=>?@^_`{|}~]+)\$"
        )
        private val csPrefixPattern = Pattern.compile(
            "^([A-Z0-9-]{1,24})\$"
        )

        /** Creates a new CryptoString object from a string in CryptoString format or null if
         *  invalid.
         */
        fun fromString(value: String): CryptoString? {
            if (!csPattern.matcher(value).matches()) return null

            val parts = value.split(":")
            if (parts.size != 2) return null
            return CryptoString(parts[0], parts[1])
        }

        /** Creates a new CryptoString from a string containing the algorithm and raw data */
        fun fromBytes(algorithm: String, buffer: ByteArray): CryptoString? {

            if (!csPrefixPattern.matcher(algorithm).matches() || buffer.isEmpty()) return null

            return CryptoString(algorithm, Base85.rfc1924Encoder.encode(buffer))
        }
    }
}