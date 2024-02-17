package libmensago

import keznacl.CryptoString
import keznacl.Encryptor
import keznacl.SecretKey

/**
 * This contains the encrypted header information for a Mensago system message.
 */
class SysEnvelope private constructor (val subtype: String, receiver: RecipientInfo,
                                       sender: SenderInfo, payloadKey: CryptoString,
                                       keyHash: CryptoString, message: Message
):
    Envelope(receiver, sender, payloadKey, keyHash, message) {

    init {
        type = MsgType.System
    }

    /**
     * Creates a SealedSysEnvelope instance from the existing
     */
    fun seal(senderKey: Encryptor, receiverKey: Encryptor): Result<SealedSysEnvelope> {
        TODO("Implement SysEnvelope::seal($senderKey, $receiverKey)")
    }

    companion object {
        fun new(receiver: RecipientInfo, sender: SenderInfo, payloadKey: SecretKey):
                Result<Envelope> {
            TODO("Implement SysEnvelope::new($receiver, $sender, $payloadKey)")
        }
    }
}
