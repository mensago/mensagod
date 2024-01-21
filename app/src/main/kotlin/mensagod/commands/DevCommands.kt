package mensagod.commands

enum class DeviceStatus {
    Active,
    Pending,
    Blocked;

    override fun toString(): String {
        return when (this) {
            Active -> "active"
            Pending -> "pending"
            Blocked -> "blocked"
        }
    }

    companion object {

        fun fromString(s: String): DeviceStatus? {
            return when (s.lowercase()) {
                "active" -> Active
                "pending" -> Pending
                "blocked" -> Blocked
                else -> null
            }
        }

    }
}