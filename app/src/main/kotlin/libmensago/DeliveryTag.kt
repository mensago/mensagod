package libmensago

import keznacl.CryptoString
import keznacl.Encryptor
import libkeycard.Domain
import libkeycard.Timestamp
import libkeycard.WAddress

/**
 * The RecipientInfo class contains the information used by the receiving domain's server to
 * deliver a message to its recipient. To protect the message author's privacy, this part of the
 * delivery tag contains the full address of the recipient, but only the domain of the author.
 */
class RecipientInfo(var to: WAddress, var senderDom: Domain)

/**
 * The SenderInfo class contains the information used by the sending domain's server to
 * deliver a message to the server for its recipient. To protect the receipient's privacy, this
 * part of the delivery tag contains only the domain of the recipient, but the full address of the
 * message author so that the sending server can handle errors and perform other administration.
 */
class SenderInfo(var from: WAddress, var recipientDom: Domain)

/**
 * The DeliveryTag is a data structure class which encapsulates all information needed to deliver
 * a completely encrypted message. It is merely an intermediary class for constructing a
 * SealedDeliveryTag instance used in an Envelope object. General usage will entail creating a
 * new DeliveryTag and then calling seal().
 *
 */
class DeliveryTag private constructor(var receiver: RecipientInfo, var sender: SenderInfo,
                                      val payloadKey: CryptoString, val keyHash: CryptoString,
                                      var type: MsgType = MsgType.User,
                                      var subType: String? = null) {
    var version = 1.0f
    var date = Timestamp()

    /**
     * Creates a SealedDeliverySysTag instance ready for use in an Envelope object.
     *
     * @param senderKey The encryption key for the sender's organization. This is obtained from the
     * Encryption-Key field in the organization's keycard.
     * @param receiverKey The encryption key for the recipient's organization. This is obtained from
     * the Encryption-Key field in the keycard for the recipient's organization.
     */
    fun seal(senderKey: Encryptor, receiverKey: Encryptor): Result<SealedDeliveryTag> {
        TODO("Implement SysDeliveryTag::seal($senderKey, $receiverKey)")
    }

    companion object {

        /**
         * Create a new DeliveryTag object from the desired sender and recipient addresses and
         * message type information.
         */
        fun new(from: WAddress, to: WAddress, type: MsgType = MsgType.User,
                subType: String? = null): Result<DeliveryTag> {
            TODO("Implement DeliveryTag::new($from, $to, $type, $subType)")
        }
    }
}
