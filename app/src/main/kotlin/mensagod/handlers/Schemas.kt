package mensagod.handlers

import libmensago.MsgField
import libmensago.MsgFieldType
import libmensago.Schema

/**
 * The Schemas singleton just contains instances of all the client request schemas used by the
 * Mensago protocol.
 */
object Schemas {
    val archive = Schema(
        MsgField("Password-Hash", MsgFieldType.String, true),
        MsgField("Workspace-ID", MsgFieldType.RandomID, false),
    )

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

    val passCode = Schema(
        MsgField("Workspace-ID", MsgFieldType.RandomID, true),
        MsgField("Reset-Code", MsgFieldType.String, true),
        MsgField("Password-Hash", MsgFieldType.String, true),
        MsgField("Password-Algorithm", MsgFieldType.String, true),

        MsgField("Password-Salt", MsgFieldType.String, false),
        MsgField("Password-Parameters", MsgFieldType.String, false),
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

    val resetPassword = Schema(
        MsgField("Workspace-ID", MsgFieldType.RandomID, true),
        MsgField("Reset-Code", MsgFieldType.String, false),
        MsgField("Expires", MsgFieldType.String, false),
    )

    val rmDir = Schema(MsgField("Path", MsgFieldType.Path, true))

    val select = Schema(MsgField("Path", MsgFieldType.Path, true))

    val send = Schema(
        MsgField("Message", MsgFieldType.String, true),
        MsgField("Domain", MsgFieldType.Domain, true),
    )

    val sendLarge = Schema(
        MsgField("Size", MsgFieldType.Integer, true),
        MsgField("Hash", MsgFieldType.CryptoString, true),
        MsgField("Domain", MsgFieldType.Domain, true),
        MsgField("TempName", MsgFieldType.String, false),
        MsgField("Offset", MsgFieldType.Integer, false),
    )

    val setDeviceInfo = Schema(MsgField("Device-Info", MsgFieldType.CryptoString, true))

    val setPassword = Schema(
        MsgField("Password-Hash", MsgFieldType.String, true),
        MsgField("NewPassword-Hash", MsgFieldType.String, true),
        MsgField("NewPassword-Algorithm", MsgFieldType.String, true),

        MsgField("NewPassword-Salt", MsgFieldType.String, false),
        MsgField("NewPassword-Parameters", MsgFieldType.String, false),
    )

    val setStatus = Schema(
        MsgField("Workspace-ID", MsgFieldType.RandomID, true),
        MsgField("Status", MsgFieldType.String, true),
    )

    val upload = Schema(
        MsgField("Size", MsgFieldType.Integer, true),
        MsgField("Hash", MsgFieldType.CryptoString, true),
        MsgField("Path", MsgFieldType.Path, true),

        MsgField("Replaces", MsgFieldType.Path, false),
        MsgField("TempName", MsgFieldType.String, false),
        MsgField("Offset", MsgFieldType.Integer, false),
    )
}
