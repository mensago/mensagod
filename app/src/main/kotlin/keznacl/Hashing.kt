package keznacl

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import ove.crypto.digest.Blake2b
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest


/**
 * Returns the hashing algorithms supported by the library. Currently the only supported algorithm
 * is BLAKE2B. Other algorithms may be added at a future time.
 */
fun getSupportedHashAlgorithms(): List<String> {
    return listOf("BLAKE2B-256", "SHA-256")
}

/**
 * Returns the recommended algorithm supported by the library. If you don't know what to choose for
 * a hashing algorithm for your implementation, this will provide a good default which balances
 * speed and security.
 */
fun getPreferredHashAlgorithm(): String {
    return "BLAKE2B-256"
}

/**
 * Creates a hash of the specified data.
 *
 * @exception UnsupportedAlgorithmException Returned if the library does not support the algorithm
 * specified
 */
fun hash(data: ByteArray, algorithm: String = getPreferredHashAlgorithm()): Result<Hash> {
    if (!getSupportedHashAlgorithms().contains(algorithm))
        return Result.failure(UnsupportedAlgorithmException())

    return when (algorithm) {
        "BLAKE2B-256" -> blake2Hash(data)
        "SHA-256" -> sha256Hash(data)
        else -> Result.failure(UnsupportedAlgorithmException())
    }
}

/**
 * Computes a [Hash] of the file specified by the path parameter. This call is often helpful
 * in that the entire contents of the file are not loaded into memory during computation.
 */
fun hashFile(path: String, algorithm: String = getPreferredHashAlgorithm()): Result<Hash> {
    if (path.isEmpty()) return Result.failure(EmptyDataException())
    if (!getSupportedHashAlgorithms().contains(algorithm))
        return Result.failure(UnsupportedAlgorithmException())

    val file = try {
        File(path)
    } catch (e: Exception) {
        return Result.failure(e)
    }

    val buffer = ByteArray(8192)
    val istream = FileInputStream(file)
    val blake2b = Blake2b.Digest.newInstance(32)

    var bytesRead = istream.read(buffer)
    while (bytesRead > 0) {
        blake2b.update(buffer.sliceArray(0 until bytesRead))
        bytesRead = istream.read(buffer)
    }

    return Result.success(Hash.fromBytes(algorithm, blake2b.digest())!!)
}

/**
 * Creates a 256-bit BLAKE2B hash of the data that provides 128 bits of protection.
 *
 * @exception EmptyDataException Returned if the ByteArray given is empty
 */
fun blake2Hash(data: ByteArray): Result<Hash> {
    if (data.isEmpty()) return Result.failure(EmptyDataException())

    val blake2b = Blake2b.Digest.newInstance(32)
    blake2b.update(data)
    return Result.success(Hash.fromBytes("BLAKE2B-256", blake2b.digest())!!)
}

fun sha256Hash(data: ByteArray): Result<Hash> {
    if (data.isEmpty()) return Result.failure(EmptyDataException())
    return runCatching {
        val hasher = MessageDigest.getInstance("SHA-256")
        hasher.update(data)
        val digest = hasher.digest()
        Hash.fromBytes("SHA-256", digest)!!
    }.getOrElse { return it.toFailure() }.toSuccess()
}

/**
 * The Hash class is a [CryptoString] subclass which provides some helpful functions for easier
 * hashing and hash checks.
 */
@Serializable(with = HashAsStringSerializer::class)
class Hash private constructor(prefix: String, encodedData: String) :
    CryptoString(prefix, encodedData) {

    fun check(data: ByteArray): Result<Boolean> {
        return Result.success(
            hash(data, prefix)
                .getOrElse { return it.toFailure() }
                .toString() == value
        )
    }

    companion object {

        /**
         * Creates a new Hash object from a string containing the algorithm and raw data
         * representing an existing hash. It does not calculate a hash from the data; it instead
         * encodes raw hash data into CryptoString format. Note that this, unlike the superclass
         * version, this function will return null if given an algorithm that is not a hash
         * algorithm supported by the library.
         */
        fun fromBytes(algorithm: String, buffer: ByteArray): Hash? {
            return if (!isValidPrefix(algorithm) || buffer.isEmpty() ||
                !getSupportedHashAlgorithms().contains(algorithm)
            ) {
                null
            } else {
                Hash(algorithm, Base85.encode(buffer))
            }
        }

        /**
         * Creates a new Hash object from a string in [CryptoString] format. Null is returned if the
         * string is invalid or if the algorithm is not supported by the library.
         */
        fun fromString(value: String): Hash? {
            if (!isValid(value)) return null

            val parts = value.split(":")
            if (parts.size != 2)
                return null

            if (!getSupportedHashAlgorithms().contains(parts[0])) return null

            return Hash(parts[0], parts[1])
        }
    }
}

/**
 * Converts the CryptoString object into a [Hash] object. It will return null if the object does
 * not use a hashing algorithm or one supported by the library.
 */
fun CryptoString.toHash(): Hash? {
    return Hash.fromString(this.value)
}

object HashAsStringSerializer : KSerializer<Hash> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("Hash", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: Hash) {
        encoder.encodeString(value.toString())
    }

    override fun deserialize(decoder: Decoder): Hash {
        val out = Hash.fromString(decoder.decodeString())
            ?: throw SerializationException("Invalid value for Hash")
        return out
    }
}
