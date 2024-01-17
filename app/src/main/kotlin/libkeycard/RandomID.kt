package libkeycard

import kotlinx.serialization.Serializable
import java.util.*

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

    override fun hashCode(): Int { return value.hashCode() }

    companion object {
        fun fromString(from: String?): RandomID? {
            if (from == null) return null

            return try {
                RandomID().apply { value = UUID.fromString(from).toString().lowercase() }
            }
            catch (e: Exception) { null }
        }

        fun fromUserID(from: UserID): RandomID? {
            return if (from.type == IDType.UserID) { null }
            else { fromString(from.value) }
        }

        fun generate(): RandomID {
            return RandomID().apply { value = UUID.randomUUID().toString().lowercase() }
        }
    }

    override fun toString(): String {
        return value
    }
}
