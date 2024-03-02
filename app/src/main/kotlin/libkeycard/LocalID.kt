package libkeycard

import kotlinx.serialization.Serializable
import java.util.regex.Pattern

@Serializable
class LocalID private constructor() {
    var value: String = ""
        private set

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as LocalID
        return value == other.value
    }

    override fun hashCode(): Int {
        return value.hashCode()
    }

    companion object {
        private val localIDPattern = Pattern.compile(
            """^([\p{L}\p{M}\p{N}\-_]|\.[^.]){1,64}$""", Pattern.CASE_INSENSITIVE
        )

        fun fromString(value: String?): LocalID? {
            if (value == null) return null
            if (!localIDPattern.matcher(value).matches()) return null

            val out = LocalID()
            out.value = value.lowercase()

            return out
        }

        /** Returns true if the supplied data matches the expected data format */
        fun checkFormat(value: String): Boolean {
            return localIDPattern.matcher(value).matches()
        }
    }

    override fun toString(): String {
        return value
    }
}
