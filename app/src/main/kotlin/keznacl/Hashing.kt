package keznacl

import ove.crypto.digest.Blake2b
import java.io.File
import java.io.FileInputStream

/**
 * Returns the hashing algorithms supported by the library. Currently the only supported algorithm is
 * BLAKE2B. Other algorithms may be added at a future time.
 */
fun getSupportedHashAlgorithms(): List<String> {
    return listOf("BLAKE2B-256")
}

/**
 * Returns the recommended algorithm supported by the library. If you don't know what to choose for a hashing algorithm
 * for your implementation, this will provide a good default which balances speed and security.
 */
fun getPreferredHashAlgorithm(): String {
    return "BLAKE2B-256"
}

fun hash(data: ByteArray, reqAlgorithm: String? = null): Result<CryptoString> {
    val algorithm = reqAlgorithm ?: getPreferredHashAlgorithm()
    if (!isSupportedAlgorithm(algorithm)) return Result.failure(UnsupportedAlgorithmException())

    return when (algorithm) {
        "BLAKE2B-256" -> blake2Hash(data)
        else -> Result.failure(UnsupportedAlgorithmException())
    }
}

/**
 * hashFile computes a hash of the file specified by the path parameter. This call is often helpful
 * in that the entire contents of the file are not loaded into memory during computation.
 */
fun hashFile(path: String, algorithm: String = getPreferredHashAlgorithm()): Result<CryptoString> {
    if (path.isEmpty()) return Result.failure(EmptyDataException())
    if (algorithm != "BLAKE2B-256") return Result.failure(UnsupportedAlgorithmException())
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

    return Result.success(CryptoString.fromBytes(algorithm, blake2b.digest())!!)
}

fun blake2Hash(data: ByteArray): Result<CryptoString> {
    if (data.isEmpty()) return Result.failure(EmptyDataException())

    val blake2b = Blake2b.Digest.newInstance(32)
    blake2b.update(data)
    return Result.success(CryptoString.fromBytes("BLAKE2B-256", blake2b.digest())!!)
}

class Hash private constructor(prefix: String, encodedData: String) :
    CryptoString(prefix, encodedData) {

    fun check(data: ByteArray): Result<Boolean> {
        TODO("Implement Hash::check($data)")
    }

    companion object {

        /** Creates a new CryptoString from a string containing the algorithm and raw data */
        fun fromBytes(algorithm: String, buffer: ByteArray): Hash? {
            return if (!isValidPrefix(algorithm) || buffer.isEmpty() ||
                !getSupportedHashAlgorithms().contains(algorithm)
            ) {
                null
            } else {
                Hash(algorithm, Base85.rfc1924Encoder.encode(buffer))
            }
        }

        /**
         * Creates a new Hash object from a string in CryptoString format. Null is returned if the
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

        fun fromCryptoString(cs: CryptoString): Hash? {
            TODO("Implement Hash::fromCryptoString()")
        }
    }
}
