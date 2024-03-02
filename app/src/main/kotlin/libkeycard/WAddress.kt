package libkeycard

import kotlinx.serialization.Serializable

@Serializable
class WAddress private constructor(val id: RandomID, val domain: Domain) {

    val address = "$id/$domain"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as WAddress
        return address == other.address
    }

    override fun hashCode(): Int {
        return address.hashCode()
    }

    override fun toString(): String {
        return address
    }

    companion object {

        /** Returns true if the supplied data matches the expected data format */
        fun checkFormat(value: String): Boolean {
            val parts = value.split("/")
            if (parts.size != 2) return false
            return RandomID.checkFormat(parts[0]) && Domain.checkFormat(parts[1])
        }

        fun fromParts(randomID: RandomID, domain: Domain): WAddress {
            return WAddress(randomID, domain)
        }

        fun fromString(value: String?): WAddress? {
            if (value == null) return null

            val parts = value.split("/")
            if (parts.size != 2) return null

            val wid = RandomID.fromString(parts[0]) ?: return null
            val dom = Domain.fromString(parts[1]) ?: return null

            return WAddress(wid, dom)
        }

        fun fromMAddress(addr: MAddress): WAddress? {
            val id = RandomID.fromUserID(addr.userid) ?: return null
            return fromParts(id, addr.domain)
        }
    }
}