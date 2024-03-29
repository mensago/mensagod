package libmensago

import keznacl.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import libkeycard.Timestamp
import java.io.File
import java.io.IOException
import java.security.GeneralSecurityException

/**
 * SealedDeliveryTag is an encrypted DeliveryTag. The receiver tag is decryptable only by the server
 * handling message delivery for the recipient. The sender tag is readable only by the server
 * carrying the message to the next hop on the behalf of the message author.
 *
 * This class is not intended to be instantiated directly, but rather either from readFromFile() or
 * DeliveryTag::seal().
 */
@Serializable
class SealedDeliveryTag(
    val receiver: CryptoString, val sender: CryptoString, val type: MsgType,
    val date: Timestamp, val payloadKey: CryptoString,
    val keyHash: Hash, val subType: String? = null,
    val version: Float
) {

    /**
     * Decrypts the encrypted recipient information in the message using the organization's
     * decryption key.
     *
     * @throws IllegalArgumentException Returned if there was a Base85 decoding error
     * @throws GeneralSecurityException Returned for decryption failures
     */
    fun decryptReceiver(keyPair: EncryptionPair): Result<RecipientLabel> {
        return decryptAndDeserialize<RecipientLabel>(receiver, keyPair)
    }

    /**
     * Decrypts the encrypted recipient information in the message using the organization's
     * decryption key.
     *
     * @throws IllegalArgumentException Returned if there was a Base85 decoding error
     * @throws GeneralSecurityException Returned for decryption failures
     */
    fun decryptSender(keyPair: EncryptionPair): Result<SenderLabel> {
        return decryptAndDeserialize<SenderLabel>(sender, keyPair)
    }

    companion object {

        /**
         * Creates a new SealedDeliveryTag instance from a file.
         *
         * @throws IOException Returned if there was an I/O error
         * @throws BadValueException Returned if the file header could not be parsed
         * @throws kotlinx.serialization.SerializationException encoding-specific errors
         * @throws IllegalArgumentException if the encoded input does not comply format's specification
         */
        fun readFromFile(file: File): Result<SealedDeliveryTag> {

            val data = readEnvelopeFile(file, true)
                .getOrElse { return it.toFailure() }

            val out = runCatching {
                Json.decodeFromString<SealedDeliveryTag>(data.first)
            }.getOrElse { return it.toFailure() }

            return out.toSuccess()
        }
    }
}

