package libmensago

import kotlinx.serialization.Serializable

@Serializable
class CmdStatus(var code: Int, var description: String, var info: String) {
    override fun toString(): String {
        return if (info.isEmpty()) "$code: $description"
        else "$code: $description ($info)"
    }
}
