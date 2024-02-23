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
