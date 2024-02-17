package libmensago

import keznacl.CryptoString
import keznacl.SecretKey
import libkeycard.Domain
import libkeycard.Timestamp
import libkeycard.WAddress

/**
 * The RecipientInfo class contains the information used by the receiving domain's server to
 * deliver a message to its recipient.
 */
class RecipientInfo(var to: WAddress, var senderDom: Domain)

/**
 * The SenderInfo class contains the information used by the sending domain's server to
 * deliver a message to the server for its recipient.
 */
class SenderInfo(var from: WAddress, var recipientDom: Domain)

/**
 * The Envelope is a data structure class which represents the public delivery information for a
 * message. Its main purpose is for packaging message data for delivery and providing a way to
 * interact with the custom serialization format it uses on disk.
 */
open class Envelope protected constructor(var receiver: RecipientInfo, var sender: SenderInfo,
                                          val payloadKey: CryptoString, val keyHash: CryptoString, val message: Message
) {
    var version = 1.0f
    var date = Timestamp()
    var type = MsgType.User

    companion object {
        fun new(receiver: RecipientInfo, sender: SenderInfo, payloadKey: SecretKey):
                Result<Envelope> {
            TODO("Implement Envelope::new($receiver, $sender, $payloadKey)")
        }
    }
}
