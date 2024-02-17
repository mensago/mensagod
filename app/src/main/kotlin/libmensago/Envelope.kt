package libmensago

import keznacl.BadValueException
import keznacl.CryptoString
import keznacl.EncryptionPair
import keznacl.Encryptor
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
     */
    fun open(keyPair: EncryptionPair): Result<Message> {
        TODO("Implement Envelope::open($keyPair)")
    }

    // TODO: Implement toString()
    // TODO: Implement saveFile()

    companion object {

        /**
         * Creates a new Envelope object representing a ready-to-send encrypted message.
         */
        fun seal(key: Encryptor, message: Message): Result<Envelope> {
            TODO("Implement Envelope::seal($key, $message")
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
fun readEnvelopeFile(file: File, headerOnly: Boolean): Result<Pair<String,String>> {

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

    if (headerOnly) return Result.success(Pair(headerLines.joinToString(), ""))

    TODO("Finish readEnvelopeFile($file, $headerOnly")

//    return Result.success(out)
}
