package libmensago

import keznacl.Encryptor
import keznacl.SecretKey
import keznacl.serializeAndEncrypt
import kotlinx.serialization.Serializable
import libkeycard.Domain
import libkeycard.Timestamp
import libkeycard.WAddress

/**
 * The RecipientLabel class contains the information used by the receiving domain's server to
 * deliver a message to its recipient. To protect the message author's privacy, this part of the
 * delivery tag contains the full address of the recipient, but only the domain of the author.
 */
@Serializable
class RecipientLabel(var to: WAddress, var senderDom: Domain)

/**
 * The SenderLabel class contains the information used by the sending domain's server to
 * deliver a message to the server for its recipient. To protect the receipient's privacy, this
 * part of the delivery tag contains only the domain of the recipient, but the full address of the
 * message author so that the sending server can handle errors and perform other administration.
 */
@Serializable
class SenderLabel(var from: WAddress, var recipientDom: Domain)

/**
 * The DeliveryTag is a data structure class which encapsulates all information needed to deliver
 * a completely encrypted message. It is merely an intermediary class for constructing a
 * SealedDeliveryTag instance used in an Envelope object. General usage will entail creating a
 * new DeliveryTag and then calling seal().
 *
 */
class DeliveryTag private constructor(
    var receiver: RecipientLabel, var sender: SenderLabel,
    val payloadKey: SecretKey, var type: MsgType = MsgType.User,
    var subType: String? = null
) {
    var version = 1.0f
    var date = Timestamp()

    /**
     * Creates a SealedDeliverySysTag instance ready for use in an Envelope object. The recipientKey
     * parameter is intentionally vague. Determining whether to use asymmetric or symmetric
     * encryption and the algorithm used requires additional context to determine. So long as the
     * encryption key used can be decrypted by the recipient, the specific don't matter as far as
     * this call is concerned.
     *
     * @param recipientKey An encryption key used for communicating with the recipient.
     * @param senderKey The encryption key for the sender's organization. This is obtained from the
     * Encryption-Key field in the organization's keycard.
     * @param receiverKey The encryption key for the recipient's organization. This is obtained from
     * the Encryption-Key field in the keycard for the recipient's organization.
     */
    fun seal(recipientKey: Encryptor, senderKey: Encryptor, receiverKey: Encryptor):
            Result<SealedDeliveryTag> {

        val encReceiver = serializeAndEncrypt(receiver, receiverKey)
            .getOrElse { return Result.failure(it) }
        val encSender = serializeAndEncrypt(sender, senderKey)
            .getOrElse { return Result.failure(it) }
        val encPayKey = recipientKey.encrypt(payloadKey.key.value.encodeToByteArray())
            .getOrElse { return Result.failure(it) }

        return Result.success(
            SealedDeliveryTag(
                encReceiver, encSender, type, date, encPayKey,
                recipientKey.getPublicHash().getOrElse { return Result.failure(it) },
                subType, version
            )
        )
    }

    companion object {

        /**
         * Create a new DeliveryTag object from the desired sender and recipient addresses and
         * message type information.
         */
        fun new(
            from: WAddress, to: WAddress, type: MsgType = MsgType.User,
            subType: String? = null
        ): Result<DeliveryTag> {

            val rInfo = RecipientLabel(to, from.domain)
            val sInfo = SenderLabel(from, to.domain)
            val payKey = SecretKey.generate().getOrElse { return Result.failure(it) }

            return Result.success(DeliveryTag(rInfo, sInfo, payKey, type, subType))
        }

        fun fromMessage(message: Message): Result<DeliveryTag> {
            return Result.success(
                DeliveryTag(
                    RecipientLabel(message.to, message.from.domain),
                    SenderLabel(message.from, message.to.domain),
                    SecretKey.generate().getOrElse { return Result.failure(it) },
                    message.type,
                    message.subType
                )
            )
        }
    }
}
