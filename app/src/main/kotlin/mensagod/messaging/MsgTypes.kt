package mensagod.messaging

import keznacl.CryptoString
import libkeycard.Domain
import libkeycard.MAddress
import libkeycard.RandomID
import libkeycard.Timestamp
import java.io.File

/**
 * SealedEnvelope is used for storing envelope data which is still completely encrypted.
 */
class SealedEnvelope(val type: String, val version: String, val receiver: CryptoString,
                     val sender: CryptoString, val date: Timestamp, val payloadKey: CryptoString) {

    fun decryptReceiver(): Result<String> {
        TODO("Implement SealedEnvelope::decryptReceiver()")
    }

    companion object {
        fun readFromFile(file: File): Result<SealedEnvelope> {
            TODO("Implement SealedEnvelope::readFromFile($file)")
        }
    }
}

/**
 * The RecipientInfo class contains the information used by the receiving domain's server to
 * deliver a message to its recipient.
 */
class RecipientInfo(var to: MAddress, var senderDom: Domain)

/**
 * The SenderInfo class contains the information used by the sending domain's server to
 * deliver a message to the server for its recipient.
 */
class SenderInfo(var from: MAddress, var recipientDom: Domain)

/**
 * The Envelope is a data structure class which represents the public delivery information for a
 * message.
 */
class Envelope(var type: String, var version: String, var receiver: RecipientInfo,
               var sender: SenderInfo, var date: Timestamp, var payloadKey: CryptoString)

/**
 * The Attachment class holds the data used for file attachments to messages and other data models
 */
class Attachment(var name: String, var type: String, var data: String)

/** The MsgBody class is a model for unencrypted messages */
class MsgBody(var from: String, var to: String, var date: Timestamp, var threadID: RandomID,
              var subject: String, var body: String, var attachments: MutableList<Attachment>)
