package libkeycard

/**
 * The MAddress class represents an identity on the Mensago platform. It can contain a Mensago
 * address, which is roughly equivalent to an e-mail address on the platform, or a workspace
 * address, which is an anonymous identifier for the represented entity. This class ensures that
 * the data contained within it is valid and usable.
 *
 * For specific information about formatting and limitations of both Mensago and workspace
 * addresses, please consult the Mensago platform overview.
 */
class MAddress private constructor(val userid: UserID, val domain: Domain) {

    val address = "$userid/$domain"
    val isWorkspace = (userid.type == IDType.WorkspaceID)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as MAddress
        return address == other.address
    }

    override fun hashCode(): Int { return address.hashCode() }

    companion object {

        fun fromParts(userid: UserID, domain: Domain): MAddress {
            return MAddress(userid, domain)
        }

        fun fromString(value: String?): MAddress? {
            if (value == null) return null

            val parts = value.split("/")
            if (parts.size != 2) return null

            val uid = UserID.fromString(parts[0]) ?: return null
            val dom = Domain.fromString(parts[1]) ?: return null

            return MAddress(uid, dom)
        }

        fun fromWAddress(waddr: WAddress): MAddress {
            return MAddress(UserID.fromWID(waddr.id), waddr.domain)
        }
    }

    override fun toString(): String {
        return address
    }
}