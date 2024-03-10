package mensagod.handlers

import libmensago.MsgField
import libmensago.MsgFieldType
import libmensago.Schema

/**
 * The Schemas singleton just contains instances of all the client request schemas used by the
 * Mensago protocol.
 */
object Schemas {
    // CANCEL has no schema

    val copy = Schema(
        MsgField("SourceFile", MsgFieldType.Path, true),
        MsgField("DestDir", MsgFieldType.Path, true)
    )

    // DELETE has a variable schema, so no entry exists here.

    val devkey = Schema(
        MsgField("Device-ID", MsgFieldType.RandomID, true),
        MsgField("Old-Key", MsgFieldType.CryptoString, true),
        MsgField("New-Key", MsgFieldType.CryptoString, true),
    )

    val devkeyClientResponse = Schema(
        MsgField("Response", MsgFieldType.String, true),
        MsgField("New-Response", MsgFieldType.String, true),
    )

    val device = Schema(
        MsgField("Device-ID", MsgFieldType.RandomID, true),
        MsgField("Device-Key", MsgFieldType.CryptoString, true),
        MsgField("Device-Info", MsgFieldType.CryptoString, false),
    )

    val exists = Schema(MsgField("Path", MsgFieldType.Path, true))

    // GETCARD is too complicated for standard schema verification
    // GETDEVICEINFO doesn't needs a preallocated schema - 1 optional parameter

    val getWID = Schema(
        MsgField("User-ID", MsgFieldType.UserID, true),
        MsgField("Domain", MsgFieldType.Domain, false)
    )

    val getUpdates = Schema(
        MsgField("Time", MsgFieldType.UnixTime, true)
    )

    val idle = Schema(
        MsgField("CountUpdates", MsgFieldType.UnixTime, false)
    )

    val list = Schema(
        MsgField("Time", MsgFieldType.UnixTime, false),
        MsgField("Path", MsgFieldType.Path, false)
    )

    val listDirs = Schema(
        MsgField("Path", MsgFieldType.Path, false)
    )

    val mkDir = Schema(
        MsgField("ClientPath", MsgFieldType.CryptoString, true),
        MsgField("Path", MsgFieldType.Path, true)
    )

    val move = Schema(
        MsgField("SourceFile", MsgFieldType.Path, true),
        MsgField("DestDir", MsgFieldType.Path, true)
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

    val register = Schema(
        // One of these is required, so a bit more validation once the schema code validates. :/
        MsgField("Workspace-ID", MsgFieldType.RandomID, false),
        MsgField("User-ID", MsgFieldType.UserID, false),

        MsgField("Password-Hash", MsgFieldType.String, true),
        MsgField("Password-Algorithm", MsgFieldType.String, true),
        MsgField("Device-ID", MsgFieldType.RandomID, true),
        MsgField("Device-Key", MsgFieldType.CryptoString, true),
        MsgField("Device-Info", MsgFieldType.CryptoString, true),

        MsgField("Password-Salt", MsgFieldType.String, false),
        MsgField("Password-Parameters", MsgFieldType.String, false),
    )

    val removeDevice = Schema(MsgField("Device-ID", MsgFieldType.RandomID, true))

    val rmDir = Schema(MsgField("Path", MsgFieldType.Path, true))

    val select = Schema(MsgField("Path", MsgFieldType.Path, true))

    val send = Schema(
        MsgField("Message", MsgFieldType.String, true),
        MsgField("Domain", MsgFieldType.Domain, true),
    )

    val setDeviceInfo = Schema(MsgField("Device-Info", MsgFieldType.CryptoString, true))
}
