package libmensago

/**
 * The MsgFormat class represents the text format contained in a message. Currently the only
 * supported formats are plaintext and SDF.
 */
enum class MsgFormat {
    Text,
    SDF;

    override fun toString(): String {
        return when(this) {
            Text -> "text"
            SDF -> "sdf"
        }
    }

    companion object {
        fun fromString(s: String): MsgFormat? {
            return when (s.lowercase()) {
                "text" -> Text
                "sdf" -> SDF
                else -> null
            }
        }
    }
}

/** Enumeration which represents the type of quoting to be used in generating message replies */
enum class QuoteType {
    None,
    Top,
    Bottom,
}

/** The main type of a message, which can be User or System */
enum class MsgType {
    User,
    System;

    override fun toString(): String {
        return when(this) {
            User -> "usermessage"
            System -> "sysmessage"
        }
    }

    companion object {
        fun fromString(s: String): MsgType? {
            return when (s.lowercase()) {
                "usermessage", "user" -> User
                "sysmessage", "system" -> System
                else -> null
            }
        }
    }
}
