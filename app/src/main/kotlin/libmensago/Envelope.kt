package libmensago

import keznacl.*
import libkeycard.HashMismatchException
import libkeycard.MissingDataException
import java.io.File
import java.io.IOException

/**
 * Envelope is a representation of an encrypted message and its associated delivery tag. Its main
 * purpose is to provide a simple, high-level API to encrypt and decrypt messages and provide
 * easy serialization and deserialization. If you're just interested in sending a message, create
 * your message, grab the encryption key for the recipient, and call seal().
 */
class Envelope(var tag: SealedDeliveryTag, var message: CryptoString) {

    /**
     * Returns the decrypted message contained in the envelope.
     *
     * @throws HashMismatchException Returned if the hash of the public key does not match that of
     * the key hash in the delivery tag.
     */
    fun open(keyPair: EncryptionPair): Result<Message> {

        val pubHash = hash(keyPair.publicKey.toByteArray(), tag.keyHash.prefix)
            .getOrElse { return Result.failure(it) }
        if (pubHash != tag.keyHash) return Result.failure(HashMismatchException())

        val payloadKeyStr = keyPair.decrypt(tag.payloadKey)
            .getOrElse { return Result.failure(it) }
            .decodeToString()
        val msgKey = SecretKey.fromString(payloadKeyStr).getOrElse { return Result.failure(it) }
        return decryptAndDeserialize<Message>(message, msgKey)
    }

    // TODO: Implement toString()
    // TODO: Implement saveFile()

    companion object {

        /**
         * Creates a new Envelope object representing a ready-to-send encrypted message.
         *
         * @exception ResourceNotFoundException Returned if the management record doesn't exist
         * @exception BadValueException Returned for bad data in the management record
         * @exception MissingDataException Returned if a required key is missing from the management record
         * @exception IOException Returned if there was a DNS lookup error
         * @exception UnsupportedAlgorithmException Returned if the library doesn't support the
         * encryption algorithm used by one of the servers
         */
        fun seal(recipientKey: Encryptor, message: Message, dns: DNSHandler):
                Result<Envelope> {

            // To do this, we need to create a DeliveryTag and then seal() it, and then encrypt
            // the message itself with the recipient's key. Pretty simple, actually.

            val senderRec = KCCache.getMgmtRecord(message.from.domain, dns)
                .getOrElse { return Result.failure(it) }
            val senderKey = senderRec.ek.toEncryptionKey()
                .getOrElse { return Result.failure(it) }
            val receiverRec = KCCache.getMgmtRecord(message.to.domain, dns)
                .getOrElse { return Result.failure(it) }
            val receiverKey = receiverRec.ek.toEncryptionKey()
                .getOrElse { return Result.failure(it) }

            val tag = DeliveryTag.fromMessage(message).getOrElse { return Result.failure(it) }
            val sealedTag = tag.seal(recipientKey, senderKey, receiverKey)
                .getOrElse { return Result.failure(it) }

            val payload = serializeAndEncrypt(message, recipientKey)
                .getOrElse { return Result.failure(it) }

            return Result.success(Envelope(sealedTag, payload))
        }

        /**
         * Reads the specified file and returns an Envelope object
         */
        fun loadFile(file: File): Result<Envelope> {

            val data = readEnvelopeFile(file, false)
                .getOrElse { return Result.failure(it) }

            TODO("Finish implementing Envelope::readFromFile($file")
        }
    }
}

/**
 * Reads the data from an envelope file and possibly also the encrypted message. It performs no
 * processing of the data at all.
 *
 * @param headerOnly Specify whether or not to read just the header or the entire file. If this
 * parameter is true, the second string is empty.
 *
 * @throws IOException Returned if there was an I/O error
 */
fun readEnvelopeFile(file: File, headerOnly: Boolean): Result<Pair<String, String>> {

    var ready = false
    val reader = file.bufferedReader()
    do {
        val line = try {
            reader.readLine()
        } catch (e: Exception) {
            return Result.failure(e)
        }
        if (line.trim() == "MENSAGO") {
            ready = true
            break
        }
    } while (line != null)

    if (!ready) return Result.failure(BadValueException())

    val headerLines = mutableListOf<String>()
    do {
        val line = try {
            reader.readLine()
        } catch (e: Exception) {
            return Result.failure(e)
        }
        if (line.trim() == "----------")
            break
        headerLines.add(line)
    } while (line != null)

    if (headerOnly) return Result.success(Pair(headerLines.joinToString(), ""))

    TODO("Finish readEnvelopeFile($file, $headerOnly")

//    return Result.success(out)
}
