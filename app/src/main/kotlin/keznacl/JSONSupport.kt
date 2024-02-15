package keznacl

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.security.GeneralSecurityException

/**
 * Serializes an object to JSON and returns the encrypted version of it.
 *
 * @throws kotlinx.serialization.SerializationException Returned for encoding-specific errors
 * @throws IllegalArgumentException Returned if the encoded input does not comply format's
 * specification
 * @throws GeneralSecurityException Returned for errors during the encryption process.
 */
inline fun <reified T>serializeAndEncrypt(obj: T, key: Encryptor): Result<CryptoString> {
    val rawJSON = try { Json.encodeToString(obj) }
        catch (e: Exception) { return Result.failure(e) }
    return key.encrypt(rawJSON.encodeToByteArray())
}

/**
 * Serializes an object to JSON and returns the encrypted version of it.
 *
 * @throws kotlinx.serialization.SerializationException Returned for encoding-specific errors
 * @throws IllegalArgumentException Returned if the encoded input does not comply format's
 * specification
 * @throws GeneralSecurityException Returned for errors during the encryption process.
 */
inline fun <reified T>decryptAndDeserialize(cs: CryptoString, key: EncryptionPair): Result<T> {
    val rawJSON = key.decrypt(cs).getOrElse { return Result.failure(it) }.decodeToString()
    val out = try { Json.decodeFromString<T>(rawJSON) }
        catch (e: Exception) { return Result.failure(e) }
    return Result.success(out)
}
