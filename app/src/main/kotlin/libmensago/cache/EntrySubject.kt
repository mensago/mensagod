package libmensago.cache;

import libkeycard.Domain
import libkeycard.MAddress
import libkeycard.UserID;

/**
 * A EntrySubject is a special data class which can be either a Mensago address or just a
 * domain. It is used in keycard caching.
 */
class EntrySubject(var domain: Domain, var id: UserID? = null) {
    companion object {
        fun fromString(s: String): EntrySubject? {
            val maddr = MAddress.fromString(s)
            val dom = Domain.fromString(s)
            return EntrySubject(maddr?.domain ?: dom ?: return null, maddr?.userid)
        }
    }
}
