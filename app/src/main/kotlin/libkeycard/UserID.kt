package libkeycard

import kotlinx.serialization.Serializable
import java.util.regex.Pattern

enum class IDType {
    WorkspaceID,
    UserID,
}

@Serializable
class UserID private constructor() {
    var value: String = ""
        private set
    var type: IDType = IDType.UserID
        private set

    fun toWID(): RandomID? {
        return RandomID.fromUserID(this)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as UserID
        if (type != other.type) return false
        return value == other.value
    }

    override fun hashCode(): Int {
        return value.hashCode()
    }

    companion object {
        private val userIDPattern = Pattern.compile("""^([\w\-]|\.[^.]){1,64}$""")
        private val randomIDPattern = Pattern.compile(
            """^[\da-fA-F]{8}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{12}$"""
        )

        /** Returns true if the supplied data matches the expected data format */
        fun checkFormat(value: String): Boolean {
            return userIDPattern.matcher(value).matches() ||
                    randomIDPattern.matcher(value).matches()
        }

        fun fromString(value: String?): UserID? {
            if (value == null) return null
            if (!userIDPattern.matcher(value).matches()) return null

            val out = UserID()
            out.value = value.lowercase()

            if (randomIDPattern.matcher(value).matches()) out.type = IDType.WorkspaceID

            return out
        }

        fun fromWID(wid: RandomID): UserID {
            val out = UserID()
            out.value = wid.toString().lowercase()
            out.type = IDType.WorkspaceID
            return out
        }
    }

    override fun toString(): String {
        return value
    }
}