package mensagod.commands

import mensagod.ClientSession
import mensagod.DBConn
import mensagod.LocalFS
import mensagod.dbcmds.addKeyInfo
import mensagod.dbcmds.getDeviceStatus
import mensagod.dbcmds.updateDeviceStatus
import mensagod.libmensago.MServerPath
import mensagod.logError
import org.apache.commons.io.FileUtils

fun commandKeyPkg(state: ClientSession) {

    if (!state.requireLogin()) return
    val devID = state.getRandomID("Device-ID", true) ?: return
    val keyInfo = state.getCryptoString("Key-Info", true) ?: return

    val db = DBConn()
    val devStatus = getDeviceStatus(db, state.wid!!, devID).getOrElse {
        logError("commandKeyPkg.getDeviceState exception for ${state.wid!!}: $it")
        ServerResponse.sendInternalError("Error getting device status",
            state.conn)
        return
    }

    when (devStatus) {
        DeviceStatus.Blocked -> {
            ServerResponse.sendForbidden("Device has already been blocked", state.conn)
            return
        }
        DeviceStatus.Registered -> {
            ServerResponse(201, "REGISTERED", "Device already registered")
                .sendCatching(state.conn,
                    "Error sending device-already-registered message")
            return
        }
        DeviceStatus.NotRegistered -> {
            ServerResponse(404, "NOT FOUND", "Device not registered")
                .sendCatching(state.conn,
                    "Error sending device-not-registered message")
            return
        }
        DeviceStatus.Approved -> {
            ServerResponse(203, "APPROVED", "Device already approved")
                .sendCatching(state.conn, "Error sending device-already-registered message")
            return
        }
        DeviceStatus.Pending -> { /* Move on from this block */ }
    }

    // We got this far, so it means that we need to save the key information to a safe place and
    // notify the client of completion

    val lfs = LocalFS.get()
    val tempHandle = lfs.makeTempFile(state.wid!!, keyInfo.value.length.toLong())
        .getOrElse {
            logError("commandKeyPkg.makeTempFile exception for ${state.wid!!}: $it")
            ServerResponse.sendInternalError("Error creating key info file", state.conn)
            return
        }
    try {
        FileUtils.touch(tempHandle.getFile())
        val ostream = tempHandle.getFile().outputStream()
        ostream.write(keyInfo.value.encodeToByteArray())
    } catch (e: Exception) {
        logError("commandKeyPkg.writeTempFile exception for ${state.wid!!}: $e")
        ServerResponse.sendInternalError("Error saving key info file", state.conn)
        return
    }

    val keyInfoPath = MServerPath("/ keys ${state.wid!!}")
    val keyInfoHandle = lfs.entry(keyInfoPath)
    val exists = keyInfoHandle.exists().getOrElse {
        logError("commandKeyPkg.keyInfoDirExists exception for ${state.wid!!}: $it")
        ServerResponse.sendInternalError("Error checking for key info directory", state.conn)
        return
    }
    if (!exists) {
        keyInfoHandle.makeDirectory()?.let {
            logError("commandKeyPkg.makeKeyInfoDir exception for ${state.wid!!}: $it")
            ServerResponse.sendInternalError("Error creating key info directory", state.conn)
            return
        }
    }
    tempHandle.moveTo(keyInfoPath)?.let {
        logError("commandKeyPkg.installKeyInfo exception for ${state.wid!!}: $it")
        ServerResponse.sendInternalError("Error installing key info", state.conn)
        return
    }
    addKeyInfo(db, state.wid!!, devID, tempHandle.path)?.let {
        logError("commandKeyPkg.addKeyInfo exception for ${state.wid!!}: $it")
        ServerResponse.sendInternalError("Error adding key info to database", state.conn)
        return
    }
    updateDeviceStatus(db, state.wid!!, devID, DeviceStatus.Approved)?.let {
        logError("commandKeyPkg.updateDeviceStatus exception for ${state.wid!!}: $it")
        ServerResponse.sendInternalError("Error approving device", state.conn)
        return
    }
    ServerResponse(200, "OK")
        .sendCatching(state.conn, "Error sending device approval message")
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