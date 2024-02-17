package mensagod.libmensago

import kotlinx.serialization.Contextual
import kotlinx.serialization.Serializable
import javax.activation.MimeType

/** Represents an attachment, such as for a message, contact, or note */
@Serializable
class Attachment(var name: String, var mime: @Contextual MimeType, var data: ByteArray) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Attachment

        if (name != other.name) return false
        if (mime.toString() != other.mime.toString()) return false
        if (!data.contentEquals(other.data)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = name.hashCode()
        result = 31 * result + mime.hashCode()
        result = 31 * result + data.contentHashCode()
        return result
    }
}
