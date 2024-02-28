package mensagod.delivery

import libkeycard.Domain
import libkeycard.RandomID
import libkeycard.UserID
import libkeycard.WAddress
import libmensago.EntrySubject

/**
 * A DeliveryTarget is a special data class which can be either a full workspace address or just a
 * domain. It is used in envelope delivery headers.
 */
class DeliveryTarget(var domain: Domain, var id: RandomID? = null) {

    /** Converts the DeliveryTarget into an EntrySubject. */
    fun toEntrySubject(): EntrySubject {
        return if (id != null) EntrySubject(domain, UserID.fromWID(id!!))
        else EntrySubject(domain)
    }

    companion object {
        fun fromString(s: String): DeliveryTarget? {
            val waddr = WAddress.fromString(s)
            val dom = Domain.fromString(s)
            return DeliveryTarget(waddr?.domain ?: dom ?: return null, waddr?.id)
        }
    }
}
