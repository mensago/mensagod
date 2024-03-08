package mensagod.handlers

import keznacl.CryptoString
import libmensago.MServerPath
import libmensago.ServerResponse
import mensagod.*
import mensagod.dbcmds.addKeyInfo
import mensagod.dbcmds.getDeviceStatus
import mensagod.dbcmds.updateDeviceKey
import mensagod.dbcmds.updateDeviceStatus
import org.apache.commons.io.FileUtils

// DEVKEY(Device-ID, Old-Key, New-Key)
fun commandDevKey(state: ClientSession) {
    val schema = Schemas.devkey
    if (!state.requireLogin(schema)) return
    val devid = schema.getRandomID("Device-ID", state.message.data)!!
    val oldkey = schema.getCryptoString("Old-Key", state.message.data)!!
    val newkey = schema.getCryptoString("New-Key", state.message.data)!!

    if (devid != state.devid) {
        QuickResponse.sendForbidden("A device can update its own key", state.conn)
        return
    }

    val success = dualChallengeDevice(state, oldkey, newkey).getOrElse {
        logError("commandDevice.dualChallengeDevice exception: $it")
        QuickResponse.sendInternalError(
            "Error authenticating client device for key update",
            state.conn
        )
        return
    }
    // We don't need to send an error message to the client because that's already taken care of in
    // dualChallengeDevice()
    if (!success) return

    updateDeviceKey(DBConn(), state.wid!!, state.devid!!, newkey)?.let {
        logError("commandDevice.updateDeviceKey exception: $it")
        QuickResponse.sendInternalError("Error updating device key", state.conn)
        return
    }

    QuickResponse.sendOK("", state.conn)
}

// GETDEVICEINFO(Device-ID=null)
fun commandGetDeviceInfo(state: ClientSession) {
    TODO("Implement commandGetDeviceInfo($state)")
}

fun commandKeyPkg(state: ClientSession) {

    if (!state.requireLogin()) return
    val devID = state.getRandomID("Device-ID", true) ?: return
    val keyInfo = state.getCryptoString("Key-Info", true) ?: return

    val db = DBConn()
    val devStatus = getDeviceStatus(db, state.wid!!, devID).getOrElse {
        logError("commandKeyPkg.getDeviceState exception for ${state.wid!!}: $it")
        QuickResponse.sendInternalError(
            "Error getting device status",
            state.conn
        )
        return
    }

    when (devStatus) {
        DeviceStatus.Blocked -> {
            QuickResponse.sendForbidden("Device has already been blocked", state.conn)
            return
        }

        DeviceStatus.Registered -> {
            ServerResponse(201, "REGISTERED", "Device already registered")
                .sendCatching(
                    state.conn,
                    "Error sending device-already-registered message"
                )
            return
        }

        DeviceStatus.NotRegistered -> {
            ServerResponse(404, "NOT FOUND", "Device not registered")
                .sendCatching(
                    state.conn,
                    "Error sending device-not-registered message"
                )
            return
        }

        DeviceStatus.Approved -> {
            ServerResponse(203, "APPROVED", "Device already approved")
                .sendCatching(state.conn, "Error sending device-already-registered message")
            return
        }

        DeviceStatus.Pending -> { /* Move on from this block */
        }
    }

    // We got this far, so it means that we need to save the key information to a safe place and
    // notify the client of completion

    val lfs = LocalFS.get()
    val tempHandle = lfs.makeTempFile(state.wid!!, keyInfo.value.length.toLong())
        .getOrElse {
            logError("commandKeyPkg.makeTempFile exception for ${state.wid!!}: $it")
            QuickResponse.sendInternalError("Error creating key info file", state.conn)
            return
        }
    try {
        FileUtils.touch(tempHandle.getFile())
        val ostream = tempHandle.getFile().outputStream()
        ostream.write(keyInfo.value.encodeToByteArray())
    } catch (e: Exception) {
        logError("commandKeyPkg.writeTempFile exception for ${state.wid!!}: $e")
        QuickResponse.sendInternalError("Error saving key info file", state.conn)
        return
    }

    val keyInfoPath = MServerPath("/ keys ${state.wid!!}")
    val keyInfoHandle = lfs.entry(keyInfoPath)
    val exists = keyInfoHandle.exists().getOrElse {
        logError("commandKeyPkg.keyInfoDirExists exception for ${state.wid!!}: $it")
        QuickResponse.sendInternalError("Error checking for key info directory", state.conn)
        return
    }
    if (!exists) {
        keyInfoHandle.makeDirectory()?.let {
            logError("commandKeyPkg.makeKeyInfoDir exception for ${state.wid!!}: $it")
            QuickResponse.sendInternalError("Error creating key info directory", state.conn)
            return
        }
    }
    tempHandle.moveTo(keyInfoPath)?.let {
        logError("commandKeyPkg.installKeyInfo exception for ${state.wid!!}: $it")
        QuickResponse.sendInternalError("Error installing key info", state.conn)
        return
    }
    addKeyInfo(db, state.wid!!, devID, tempHandle.path)?.let {
        logError("commandKeyPkg.addKeyInfo exception for ${state.wid!!}: $it")
        QuickResponse.sendInternalError("Error adding key info to database", state.conn)
        return
    }
    updateDeviceStatus(db, state.wid!!, devID, DeviceStatus.Approved)?.let {
        logError("commandKeyPkg.updateDeviceStatus exception for ${state.wid!!}: $it")
        QuickResponse.sendInternalError("Error approving device", state.conn)
        return
    }
    ServerResponse(200, "OK")
        .sendCatching(state.conn, "Error sending device approval message")
}

// REMOVEDEVICE(Device-ID=null)
fun commandRemoveDevice(state: ClientSession) {
    TODO("Implement commandRemoveDevice($state)")
}

// SETDEVICEINFO(Device-Info)
fun commandSetDeviceInfo(state: ClientSession) {
    TODO("Implement commandSetDeviceInfo($state)")
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


private fun dualChallengeDevice(state: ClientSession, oldkey: CryptoString, newKey: CryptoString):
        Result<Boolean> {
    TODO("Implement dualChallengeDevice")
}