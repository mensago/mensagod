package mensagod.libmensago

import keznacl.BadValueException
import keznacl.CryptoString
import keznacl.Encryptor
import keznacl.decryptAndDeserialize
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import libkeycard.Timestamp
import mensagod.DBConn
import mensagod.dbcmds.getEncryptionPair
import mensagod.messaging.RecipientInfo
import mensagod.messaging.SenderInfo
import java.io.File

/**
 * The Envelope is a data structure class which represents the public delivery information for a
 * message.
 */
class Envelope(var type: String, var version: String, var receiver: RecipientInfo,
               var sender: SenderInfo, var date: Timestamp, var payloadKey: CryptoString
)

/**
 * SealedSysEnvelope is used for storing envelope data which is still completely encrypted.
 */
@Serializable
class SealedSysEnvelope(val type: String, val version: String, val receiver: CryptoString,
                        val sender: CryptoString, val date: Timestamp, val payloadKey: CryptoString
) {

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
         * Creates a new SealedSysEnvelope instance from a file.
         *
         * @throws IOException Returned if there was an I/O error
         * @throws BadValueException Returned if the file header could not be parsed
         * @throws kotlinx.serialization.SerializationException encoding-specific errors
         * @throws IllegalArgumentException if the encoded input does not comply format's specification
         */
        fun readFromFile(file: File): Result<SealedSysEnvelope> {

            var ready = false
            val reader = file.bufferedReader()
            do {
                val line = try { reader.readLine() }
                catch (e: Exception) { return Result.failure(e) }
                if (line.trim() == "MENSAGO") {
                    ready = true
                    break
                }
            } while (line != null)

            if (!ready) return Result.failure(BadValueException())

            val headerLines = mutableListOf<String>()
            do {
                val line = try { reader.readLine() }
                catch (e: Exception) { return Result.failure(e) }
                if (line.trim() == "----------")
                    break
                headerLines.add(line)
            } while (line != null)

            val out = try { Json.decodeFromString<SealedSysEnvelope>(headerLines.joinToString()) }
            catch (e: Exception) { return Result.failure(e) }

            return Result.success(out)
        }
    }
}

/**
 * This contains the encrypted header information for a Mensago system message.
 */
class SysEnvelope(val type: String, val version: String, val receiver: String,
                  val sender: String, val date: Timestamp
) {

    /**
     * Creates a SealedSysEnvelope instance from the existing
     */
    fun seal(senderKey: Encryptor, receiverKey: Encryptor): Result<SealedSysEnvelope> {
        TODO("Implement SysEnvelope::seal($senderKey, $receiverKey)")
    }
}