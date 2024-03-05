package libmensago

import kotlinx.serialization.Serializable
import java.util.regex.Pattern

@Serializable
class MimeType private constructor(val value: String) {

    override fun toString(): String {
        return value
    }

    companion object {
        private val mimePattern = Pattern.compile(
            "(application|audio|font|example|image|message|model|multipart|text|video|" +
                    "x-[0-9A-Za-z!#$%&'*+.^_`|~-]+)/([0-9A-Za-z!#$%&'*+.^_`|~-]+)"
        )

        /** Returns true if the supplied data matches the expected data format */
        fun checkFormat(value: String): Boolean {
            return mimePattern.matcher(value).matches()
        }

        fun fromString(from: String?): MimeType? {
            if (from == null) return null
            return if (checkFormat(from)) MimeType(from) else null
        }

    }
}