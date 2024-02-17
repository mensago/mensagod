package mensagod.libmensago

import keznacl.CryptoString
import keznacl.Encryptor

/**
 * This contains the encrypted header information for a Mensago system message.
 */
class SysEnvelope(val subtype: String, receiver: RecipientInfo, sender: SenderInfo,
                  payloadKey: CryptoString): Envelope(receiver, sender, payloadKey) {

    init {
        type = MsgType.System
    }

    /**
     * Creates a SealedSysEnvelope instance from the existing
     */
    fun seal(senderKey: Encryptor, receiverKey: Encryptor): Result<SealedSysEnvelope> {
        TODO("Implement SysEnvelope::seal($senderKey, $receiverKey)")
    }
}
