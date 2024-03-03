package mensagod.handlers

import libmensago.MsgField
import libmensago.MsgFieldType
import libmensago.Schema

/**
 * The Schemas singleton just contains instances of all the client request schemas used by the
 * Mensago protocol.
 */
object Schemas {

    val getWID = Schema(
        MsgField("User-ID", MsgFieldType.UserID, true),
        MsgField("Domain", MsgFieldType.Domain, false)
    )

    val getUpdates = Schema(
        MsgField("Time", MsgFieldType.UnixTime, true)
    )

    val mkDir = Schema(
        MsgField("ClientPath", MsgFieldType.CryptoString, true),
        MsgField("Path", MsgFieldType.Path, true)
    )

    val regCode = Schema(
        // One of these is required, so a bit more validation once the schema code validates. :/
        MsgField("Workspace-ID", MsgFieldType.RandomID, false),
        MsgField("User-ID", MsgFieldType.UserID, false),

        MsgField("Reg-Code", MsgFieldType.String, true),
        MsgField("Password-Hash", MsgFieldType.String, true),
        MsgField("Password-Algorithm", MsgFieldType.String, true),
        MsgField("Device-ID", MsgFieldType.RandomID, true),
        MsgField("Device-Key", MsgFieldType.CryptoString, true),
        MsgField("Device-Info", MsgFieldType.CryptoString, true),

        MsgField("Domain", MsgFieldType.Domain, false),
        MsgField("Password-Salt", MsgFieldType.String, false),
        MsgField("Password-Parameters", MsgFieldType.String, false),
    )
}
