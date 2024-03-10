package keznacl

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.security.GeneralSecurityException

/**
 * Serializes an object to JSON and returns the encrypted version of it.
 *
 * @exception kotlinx.serialization.SerializationException Returned for encoding-specific errors
 * @exception IllegalArgumentException Returned if the encoded input does not comply format's
 * specification
 * @exception GeneralSecurityException Returned for errors during the encryption process.
 */
inline fun <reified T> serializeAndEncrypt(obj: T, key: Encryptor): Result<CryptoString> {
    val rawJSON = runCatching { Json.encodeToString(obj) }.getOrElse { return it.toFailure() }
    return key.encrypt(rawJSON.encodeToByteArray())
}

/**
 * Serializes an object to JSON and returns the encrypted version of it.
 *
 * @exception kotlinx.serialization.SerializationException Returned for encoding-specific errors
 * @exception IllegalArgumentException Returned if the encoded input does not comply format's
 * specification
 * @exception GeneralSecurityException Returned for errors during the encryption process.
 */
inline fun <reified T> decryptAndDeserialize(cs: CryptoString, key: Decryptor): Result<T> {
    val rawJSON = key.decrypt(cs).getOrElse { return it.toFailure() }.decodeToString()
    val out = runCatching { Json.decodeFromString<T>(rawJSON) }.getOrElse { return it.toFailure() }
    
    return out.toSuccess()
}
