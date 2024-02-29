package libmensago;

import libkeycard.Domain
import libkeycard.Entry
import libkeycard.MAddress
import libkeycard.UserID;

/**
 * A EntrySubject is a special data class which can be either a Mensago address or just a
 * domain. It is primarily used in keycard caching, but can have other uses, as well.
 */
class EntrySubject(var domain: Domain, var id: UserID? = null) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as EntrySubject
        if (domain != other.domain) return false
        return (id == other.id)
    }

    override fun hashCode(): Int {
        var result = domain.hashCode()
        if (id != null)
            result = 31 * result + id.hashCode()
        return result
    }

    override fun toString(): String {
        return if (id != null) "$id/$domain" else domain.toString()
    }

    companion object {

        fun fromEntry(e: Entry): EntrySubject? {
            val domain = Domain.fromString(e.getFieldString("Domain")) ?: return null
            val uid = UserID.fromString(
                e.getFieldString("User-ID")
                    ?: e.getFieldString("Workspace-ID")
            )
            return EntrySubject(domain, uid)
        }

        fun fromString(s: String): EntrySubject? {
            val maddr = MAddress.fromString(s)
            val dom = Domain.fromString(s)
            return EntrySubject(maddr?.domain ?: dom ?: return null, maddr?.userid)
        }
    }
}
