package libmensago

import keznacl.BadValueException
import keznacl.CryptoString
import keznacl.decryptAndDeserialize
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import libkeycard.Timestamp
import mensagod.DBConn
import mensagod.DatabaseCorruptionException
import mensagod.NotConnectedException
import mensagod.ResourceNotFoundException
import mensagod.dbcmds.getEncryptionPair
import java.io.File
import java.io.IOException
import java.security.GeneralSecurityException

/**
 * SealedDeliveryTag is a completely encrypted representation of a message and its associated
 * delivery data. The main purpose of this class is for saving/loading from disk, although it could
 * be used for other purposes, as well. The receiver tag is decryptable only by the server handling
 * message delivery for the recipient. The sender tag is readable only by the server carrying the
 * message to the next hop on the behalf of the message author.
 */
@Serializable
class SealedDeliveryTag(val type: String, val version: String, val receiver: CryptoString,
                        val sender: CryptoString, val date: Timestamp, val payloadKey: CryptoString,
                        val subType: String? = null) {
    /**
     * Decrypts the encrypted recipient information in the message using the organization's
     * decryption key.
     *
     * @throws NotConnectedException Returned if not connected to the database
     * @throws ResourceNotFoundException Returned if the keypair was not found
     * @throws java.sql.SQLException Returned for database problems, most likely either with your
     * query or with the connection
     * @throws DatabaseCorruptionException if bad data was received from the database itself
     * @throws IllegalArgumentException Returned if there was a Base85 decoding error
     * @throws GeneralSecurityException Returned for decryption failures
     */
    fun decryptReceiver(): Result<RecipientInfo> {
        val keyPair = getEncryptionPair(DBConn()).getOrElse { return Result.failure(it) }
        return decryptAndDeserialize<RecipientInfo>(receiver, keyPair)
    }

    /**
     * Decrypts the encrypted recipient information in the message using the organization's
     * decryption key.
     *
     * @throws NotConnectedException Returned if not connected to the database
     * @throws ResourceNotFoundException Returned if the keypair was not found
     * @throws java.sql.SQLException Returned for database problems, most likely either with your
     * query or with the connection
     * @throws DatabaseCorruptionException if bad data was received from the database itself
     * @throws IllegalArgumentException Returned if there was a Base85 decoding error
     * @throws GeneralSecurityException Returned for decryption failures
     */
    fun decryptSender(): Result<SenderInfo> {
        val keyPair = getEncryptionPair(DBConn()).getOrElse { return Result.failure(it) }
        return decryptAndDeserialize<SenderInfo>(sender, keyPair)
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
                .getOrElse { return Result.failure(it) }

            val out = try { Json.decodeFromString<SealedDeliveryTag>(data.first) }
            catch (e: Exception) { return Result.failure(e) }

            return Result.success(out)
        }
    }
}

