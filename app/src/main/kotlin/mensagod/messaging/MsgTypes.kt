package mensagod.messaging

import keznacl.CryptoString
import keznacl.Encryptor
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import libkeycard.Domain
import libkeycard.Timestamp
import libkeycard.WAddress
import java.security.GeneralSecurityException

/**
 * The RecipientInfo class contains the information used by the receiving domain's server to
 * deliver a message to its recipient.
 */
class RecipientInfo(var to: WAddress, var senderDom: Domain) {

    /**
     * Serializes the object to JSON and returns the encrypted version
     *
     * @throws kotlinx.serialization.SerializationException Returned for encoding-specific errors
     * @throws IllegalArgumentException Returned if the encoded input does not comply format's
     * specification
     * @throws GeneralSecurityException Returned for errors during the encryption process.
     */
    fun encrypt(key: Encryptor): Result<CryptoString> {
        val rawJSON = try { Json.encodeToString(this) }
            catch(e: Exception) { return Result.failure(e) }
        return key.encrypt(rawJSON.encodeToByteArray())
    }
}

/**
 * The SenderInfo class contains the information used by the sending domain's server to
 * deliver a message to the server for its recipient.
 */
class SenderInfo(var from: WAddress, var recipientDom: Domain)

/**
 * The Envelope is a data structure class which represents the public delivery information for a
 * message.
 */
class Envelope(var type: String, var version: String, var receiver: RecipientInfo,
               var sender: SenderInfo, var date: Timestamp, var payloadKey: CryptoString)
