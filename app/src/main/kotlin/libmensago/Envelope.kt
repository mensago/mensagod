package libmensago

import keznacl.*
import kotlinx.serialization.SerializationException
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import libkeycard.HashMismatchException
import libkeycard.MissingDataException
import libmensago.resolver.KCResolver
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
     * @exception HashMismatchException Returned if the hash of the public key does not match that of
     * the key hash in the delivery tag.
     */
    fun open(keyPair: EncryptionPair): Result<Message> {

        val pubHash = hash(keyPair.pubKey.toByteArray(), tag.keyHash.getType()!!)
            .getOrElse { return it.toFailure() }
        if (pubHash != tag.keyHash) return HashMismatchException().toFailure()

        val payloadKeyStr = keyPair.decrypt(tag.payloadKey)
            .getOrElse { return it.toFailure() }
            .decodeToString()
        val msgKey = SecretKey.fromString(payloadKeyStr).getOrElse { return it.toFailure() }
        return decryptAndDeserialize<Message>(message, msgKey)
    }

    /**
     * Returns a string representing the Envelope's data in the official format. Unlike toString(),
     * this version will not throw exceptions, but otherwise functions like toString().
     */
    fun toStringResult(): Result<String> {
        return listOf("MENSAGO",
            runCatching { Json.encodeToString(tag) }.getOrElse { return it.toFailure() },
            "----------",
            message.prefix,
            message.encodedData,
            "",
            ""
        ).joinToString("\r\n")
            .toSuccess()
    }

    override fun toString(): String {
        return toStringResult().getOrThrow()
    }

    /**
     * Saves the Envelope's contents to a file using the official data format.
     *
     * @exception NullPointerException Returned if given empty data
     * @exception SecurityException Returned if a security manager exists and gets in the way
     * @exception IOException Returned if an I/O error occurs
     */
    fun saveFile(path: String): Throwable? {
        return kotlin.runCatching {
            val file = File(path)
            if (!file.exists()) file.createNewFile()
            val writer = file.bufferedWriter()
            writer.write(toString())
            writer.flush()
        }.exceptionOrNull()
    }

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
        fun seal(recipientKey: Encryptor, message: Message): Result<Envelope> {

            // To do this, we need to create a DeliveryTag and then seal() it, and then encrypt
            // the message itself with the recipient's key. Pretty simple, actually.

            val senderRec = KCResolver.getMgmtRecord(message.from.domain)
                .getOrElse { return it.toFailure() }
            val senderKey = senderRec.ek.toEncryptionKey()
                .getOrElse { return it.toFailure() }
            val receiverRec = KCResolver.getMgmtRecord(message.to.domain)
                .getOrElse { return it.toFailure() }
            val receiverKey = receiverRec.ek.toEncryptionKey()
                .getOrElse { return it.toFailure() }

            val tag = DeliveryTag.fromMessage(message).getOrElse { return it.toFailure() }
            val sealedTag = tag.seal(recipientKey, senderKey, receiverKey)
                .getOrElse { return it.toFailure() }

            val payload = serializeAndEncrypt(message, tag.payloadKey)
                .getOrElse { return it.toFailure() }

            return Result.success(Envelope(sealedTag, payload))
        }

        /**
         * Reads the specified file and returns an Envelope object
         */
        fun loadFile(file: File): Result<Envelope> {

            val data = readEnvelopeFile(file, false).getOrElse { return it.toFailure() }
            val tag = runCatching { Json.decodeFromString<SealedDeliveryTag>(data.first) }
                .getOrElse {
                    return SerializationException("Failed to deserialize delivery tag: $it")
                        .toFailure()
                }

            return Envelope(tag, data.second!!).toSuccess()
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
fun readEnvelopeFile(file: File, headerOnly: Boolean): Result<Pair<String, CryptoString?>> {

    val reader = file.bufferedReader()
    do {
        val line = runCatching {
            reader.readLine() ?: run {
                reader.close()
                return BadValueException("File missing start of header").toFailure()
            }
        }.getOrElse {
            reader.close()
            return it.toFailure()
        }.trim()

        if (line.trim() == "MENSAGO") {
            break
        }
    } while (true)

    val headerLines = mutableListOf<String>()
    do {
        val line = runCatching {
            reader.readLine() ?: run {
                reader.close()
                return MissingDataException("Premature end of header").toFailure()
            }
        }.getOrElse {
            reader.close()
            return it.toFailure()
        }.trim()

        if (line == "----------")
            break
        headerLines.add(line)
    } while (true)

    if (headerOnly) {
        reader.close()
        return Pair(headerLines.joinToString(), null).toSuccess()
    }
    val prefix = runCatching {
        reader.readLine() ?: run {
            reader.close()
            return BadValueException("File missing payload prefix").toFailure()
        }
    }.getOrElse {
        reader.close()
        return it.toFailure()
    }.trim()

    val payload = runCatching {
        reader.readLine() ?: run {
            reader.close()
            return BadValueException("File missing payload").toFailure()
        }
    }.getOrElse {
        reader.close()
        return it.toFailure()
    }.trim()

    reader.close()
    return Pair(
        headerLines.joinToString(),
        CryptoString.fromString("$prefix:$payload")
            ?: return BadValueException("Bad payload format").toFailure()
    ).toSuccess()
}
