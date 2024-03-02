package libkeycard

import kotlinx.serialization.Serializable
import java.util.regex.Pattern

/** A formatted data type class used to house Internet domains */
@Serializable
class Domain private constructor() {

    var value = ""
        private set

    /** Similar to parent() except it modifies the internal value of the instance. */
    fun pop(): Boolean {
        if (value.isEmpty()) return false

        val domParts = value.split(".")
        value = if (domParts.size > 1) {
            domParts.subList(1, domParts.size).joinToString(".")
        } else {
            ""
        }
        return true
    }

    /** Adds a domain component to the beginning of the domain object */
    fun push(subdom: String): Boolean {
        val m = domainPattern.matcher(subdom)
        if (!m.matches()) {
            return false
        }
        value = "$subdom.$value"
        return true
    }

    override fun toString(): String {
        return value
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Domain
        return value == other.value
    }

    override fun hashCode(): Int {
        return value.hashCode()
    }

    /** Returns the parent of the domain stored in the instance  */
    fun parent(): String? {
        val domParts = value.split(".")
        if (domParts.size < 3) {
            return null
        }

        return domParts.subList(1, domParts.size).joinToString(".")
    }

    companion object {
        private val domainPattern = Pattern.compile(
            "^([a-zA-Z0-9\\-]+)(\\.[a-zA-Z0-9\\-]+)*$", Pattern.CASE_INSENSITIVE
        )

        fun fromString(value: String?): Domain? {
            if (value == null) return null

            if (!domainPattern.matcher(value).matches()) return null

            val out = Domain()
            out.value = value.lowercase()
            return out
        }

        /** Returns true if the supplied data matches the expected data format */
        fun checkFormat(value: String): Boolean {
            return domainPattern.matcher(value).matches()
        }
    }

}
