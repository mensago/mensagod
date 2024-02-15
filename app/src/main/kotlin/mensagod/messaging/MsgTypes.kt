package mensagod.messaging

import keznacl.CryptoString
import libkeycard.Domain
import libkeycard.RandomID
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
 * message.
 */
class Envelope(var type: String, var version: String, var receiver: RecipientInfo,
               var sender: SenderInfo, var date: Timestamp, var payloadKey: CryptoString)

/**
 * A DeliveryTarget is a special data class which can be either a full workspace address or just a
 * domain. It is used in envelope delivery headers.
 */
class DeliveryTarget(var domain: Domain, var id: RandomID? = null) {
    companion object {

        fun fromString(s: String): DeliveryTarget? {
            TODO("Implement DeliveryTarget::fromString($s")
        }
    }
}
