package mensagod.commands

import mensagod.ClientSession
import mensagod.DBConn
import mensagod.dbcmds.getDeviceStatus

fun commandKeyPkg(state: ClientSession) {

    if (!state.requireLogin()) return
    val devID = state.getRandomID("Device-ID", true) ?: return
    val keyInfo = state.getCryptoString("Key-Info", true) ?: return

    val db = DBConn()
    val devStatus = getDeviceStatus(db, state.wid!!, devID)

    // TODO: Finish implementing commandKeyPkg()
}

enum class DeviceStatus {
    Approved,
    Blocked,
    NotRegistered,
    Pending,
    Registered;

    override fun toString(): String {
        return when (this) {
            Approved -> "approved"
            Blocked -> "blocked"
            NotRegistered -> "notregistered"
            Pending -> "pending"
            Registered -> "registered"
        }
    }

    companion object {

        fun fromString(s: String): DeviceStatus? {
            return when (s.lowercase()) {
                "approved" -> Approved
                "blocked" -> Blocked
                "notregistered" -> NotRegistered
                "pending" -> Pending
                "registered" -> Registered
                else -> null
            }
        }

    }
}