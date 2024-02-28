package mensagod.delivery

import libkeycard.Domain
import libkeycard.RandomID
import libkeycard.WAddress

/**
 * A DeliveryTarget is a special data class which can be either a full workspace address or just a
 * domain. It is used in envelope delivery headers.
 */
class DeliveryTarget(var domain: Domain, var id: RandomID? = null) {
    companion object {

        fun fromString(s: String): DeliveryTarget? {
            val waddr = WAddress.fromString(s)
            val dom = Domain.fromString(s)
            return DeliveryTarget(waddr?.domain ?: dom ?: return null, waddr?.id)
        }
    }
}
