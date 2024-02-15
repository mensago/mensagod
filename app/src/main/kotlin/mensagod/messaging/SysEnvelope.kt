package mensagod.messaging

import keznacl.Encryptor
import libkeycard.Timestamp

/**
 * This contains the encrypted header information for a Mensago system message.
 */
class SysEnvelope(val type: String, val version: String, val receiver: String,
                  val sender: String, val date: Timestamp) {

    /**
     * Creates a SealedSysEnvelope instance from the existing
     */
    fun seal(senderKey: Encryptor, receiverKey: Encryptor): Result<SealedSysEnvelope> {
        TODO("Implement SysEnvelope::seal($senderKey, $receiverKey)")
    }
}
