package libkeycard

import kotlinx.serialization.Serializable
import java.util.*
import java.util.regex.Pattern

@Serializable
class RandomID private constructor() {
    var value: String = ""
        private set

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as RandomID
        return value == other.value
    }

    override fun hashCode(): Int {
        return value.hashCode()
    }

    companion object {
        private val randomIDPattern = Pattern.compile(
            """^[\da-fA-F]{8}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{12}$"""
        )

        /** Returns true if the supplied data matches the expected data format */
        fun checkFormat(value: String): Boolean {
            return randomIDPattern.matcher(value).matches()
        }

        fun fromString(from: String?): RandomID? {
            if (from == null) return null

            return try {
                RandomID().apply { value = UUID.fromString(from).toString().lowercase() }
            } catch (e: Exception) {
                null
            }
        }

        fun fromUserID(from: UserID): RandomID? {
            return if (from.type == IDType.UserID) {
                null
            } else {
                fromString(from.value)
            }
        }

        fun generate(): RandomID {
            return RandomID().apply { value = UUID.randomUUID().toString().lowercase() }
        }
    }

    override fun toString(): String {
        return value
    }
}
