package mensagod.handlers

import keznacl.*
import libkeycard.MissingFieldException
import libmensago.ClientRequest
import libmensago.MServerPath
import libmensago.ServerResponse
import mensagod.*
import mensagod.dbcmds.*
import org.apache.commons.io.FileUtils
import java.security.SecureRandom

// DEVKEY(Device-ID, Old-Key, New-Key)
fun commandDevKey(state: ClientSession) {
    val schema = Schemas.devkey
    if (!state.requireLogin(schema)) return
    val devid = schema.getRandomID("Device-ID", state.message.data)!!
    val oldkey = schema.getCryptoString("Old-Key", state.message.data)!!
    val newkey = schema.getCryptoString("New-Key", state.message.data)!!

    if (devid != state.devid) {
        QuickResponse.sendForbidden("A device can update only its own key", state.conn)
        return
    }

    val success = dualChallengeDevice(state, oldkey, newkey).getOrElse {
        logError("commandDevice.dualChallengeDevice exception: $it")
        state.quickResponse(
            300, "INTERNAL SERVER ERROR",
            "Error authenticating client device for key update"
        )
        return
    }
    // We don't need to send an error message to the client because that's already taken care of in
    // dualChallengeDevice()
    if (!success) {
        state.quickResponse(401, "UNAUTHORIZED")
        return
    }

    updateDeviceKey(DBConn(), state.wid!!, state.devid!!, newkey)?.let {
        logError("commandDevice.updateDeviceKey exception: $it")
        state.quickResponse(
            300, "INTERNAL SERVER ERROR",
            "Error updating device key"
        )
        return
    }

    state.quickResponse(200, "OK")
}

// GETDEVICEINFO(Device-ID=null)
fun commandGetDeviceInfo(state: ClientSession) {

    if (!state.requireLogin()) return
    val devID = state.getRandomID("Device-ID", false)
    val db = DBConn()
    val infoList = getDeviceInfo(db, state.wid!!, devID).getOrElse {
        logError("commandGetDeviceInfo.getDeviceInfo exception for ${state.wid!!}: $it")
        state.quickResponse(
            300, "INTERNAL SERVER ERROR",
            "Error getting device info"
        )
        return
    }
    if (infoList.isEmpty()) {
        state.quickResponse(404, "NOT FOUND")
        return
    }
    val response = if (devID != null) {
        ServerResponse(
            200, "OK", "", mutableMapOf(
                "Device-Info" to infoList[0].second.toString()
            )
        )
    } else {
        val data = infoList.associate { Pair(it.first.toString(), it.second.toString()) }
            .toMutableMap()
        data["Devices"] = infoList.map { it.first }.joinToString(",")
        ServerResponse(200, "OK", "", data)
    }
    response.sendCatching(state.conn, "Error sending device info to $state.wid")
}

fun commandKeyPkg(state: ClientSession) {

    if (!state.requireLogin()) return
    val devID = state.getRandomID("Device-ID", true) ?: return
    val keyInfo = state.getCryptoString("Key-Info", true) ?: return

    val db = DBConn()
    val devStatus = getDeviceStatus(db, state.wid!!, devID).getOrElse {
        logError("commandKeyPkg.getDeviceState exception for ${state.wid!!}: $it")
        state.quickResponse(
            300, "INTERNAL SERVER ERROR",
            "Error getting device status"
        )
        return
    }

    when (devStatus) {
        DeviceStatus.Blocked -> {
            state.quickResponse(403, "FORBIDDEN", "Device has already been blocked")
            return
        }

        DeviceStatus.Registered -> {
            state.quickResponse(201, "REGISTERED", "Device already registered")
            return
        }

        DeviceStatus.NotRegistered -> {
            state.quickResponse(404, "NOT FOUND", "Device not registered")
            return
        }

        DeviceStatus.Approved -> {
            state.quickResponse(203, "APPROVED", "Device already approved")
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
            state.quickResponse(
                300, "INTERNAL SERVER ERROR",
                "Error creating key info file"
            )
            return
        }
    try {
        FileUtils.touch(tempHandle.getFile())
        val ostream = tempHandle.getFile().outputStream()
        ostream.write(keyInfo.value.encodeToByteArray())
    } catch (e: Exception) {
        logError("commandKeyPkg.writeTempFile exception for ${state.wid!!}: $e")
        state.quickResponse(
            300, "INTERNAL SERVER ERROR",
            "Error saving key info file"
        )
        return
    }

    val keyInfoPath = MServerPath("/ keys ${state.wid!!}")
    val keyInfoHandle = lfs.entry(keyInfoPath)
    val exists = keyInfoHandle.exists().getOrElse {
        logError("commandKeyPkg.keyInfoDirExists exception for ${state.wid!!}: $it")
        state.quickResponse(
            300, "INTERNAL SERVER ERROR",
            "Error checking for key info directory"
        )
        return
    }
    if (!exists) {
        keyInfoHandle.makeDirectory()?.let {
            logError("commandKeyPkg.makeKeyInfoDir exception for ${state.wid!!}: $it")
            state.quickResponse(
                300, "INTERNAL SERVER ERROR",
                "Error creating key info directory"
            )
            return
        }
    }
    tempHandle.moveTo(keyInfoPath)?.let {
        logError("commandKeyPkg.installKeyInfo exception for ${state.wid!!}: $it")
        state.quickResponse(
            300, "INTERNAL SERVER ERROR",
            "Error installing key info"
        )
        return
    }
    addKeyInfo(db, state.wid!!, devID, tempHandle.path)?.let {
        logError("commandKeyPkg.addKeyInfo exception for ${state.wid!!}: $it")
        state.quickResponse(
            300, "INTERNAL SERVER ERROR",
            "Error adding key info to database"
        )
        return
    }
    updateDeviceStatus(db, state.wid!!, devID, DeviceStatus.Approved)?.let {
        logError("commandKeyPkg.updateDeviceStatus exception for ${state.wid!!}: $it")
        state.quickResponse(
            300, "INTERNAL SERVER ERROR",
            "Error approving device"
        )
        return
    }
    state.quickResponse(200, "OK")
}

// REMOVEDEVICE(Device-ID=null)
fun commandRemoveDevice(state: ClientSession) {

    val schema = Schemas.removeDevice
    if (!state.requireLogin(schema)) return
    val devid = schema.getRandomID("Device-ID", state.message.data)!!

    val db = DBConn()
    removeDevice(db, state.wid!!, devid)?.let {
        logError("commandRemoveDevice.removeDevice exception for ${state.wid!!}: $it")
        state.quickResponse(
            300, "INTERNAL SERVER ERROR",
            "Error removing device"
        )
        return
    }
    state.quickResponse(200, "OK")

    if (devid == state.devid)
        state.isTerminating = true
}

// SETDEVICEINFO(Device-Info)
fun commandSetDeviceInfo(state: ClientSession) {
    val schema = Schemas.setDeviceInfo
    if (!state.requireLogin(schema)) return
    val devInfo = schema.getCryptoString("Device-Info", state.message.data)!!

    setDeviceInfo(DBConn(), state.wid!!, state.devid!!, devInfo)?.let {
        logError("commandSetDeviceInfo.setDeviceInfo exception for ${state.wid!!}: $it")
        state.quickResponse(
            300, "INTERNAL SERVER ERROR",
            "Error updating device info"
        )
        return
    }
    state.quickResponse(200, "OK")
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


private fun dualChallengeDevice(state: ClientSession, oldKey: CryptoString, newKey: CryptoString):
        Result<Boolean> {

    // This is much like challengeDevice(), but using two keys, an old one and a new one
    // - receive 2 keys
    // - send 2 challenges
    // - receive and verify 2 responses and return the result

    val rawOldKey = oldKey.toEncryptionKey().getOrElse { return it.toFailure() }
    val challenge1 = generateChallenge(rawOldKey).getOrElse { return it.toFailure() }
    val rawNewKey = newKey.toEncryptionKey().getOrElse { return it.toFailure() }
    val challenge2 = generateChallenge(rawNewKey).getOrElse { return it.toFailure() }

    ServerResponse(
        100, "CONTINUE", "",
        mutableMapOf(
            "Challenge" to challenge1.second.toString(),
            "New-Challenge" to challenge2.second.toString()
        )
    ).send(state.conn)?.let { return it.toFailure() }

    val req = ClientRequest.receive(state.conn.getInputStream())
        .getOrElse { return it.toFailure() }
    if (req.action == "CANCEL") return CancelException().toFailure()

    if (req.action != "DEVKEY") {
        state.quickResponse(400, "BAD REQUEST", "Sesion state mismatch")
        return false.toSuccess()
    }

    val schema = Schemas.devkeyClientResponse
    schema.validate(req.data) { name, e ->
        val msg = if (e is MissingFieldException)
            "Missing required field $name"
        else
            "Bad value for field $name"
        state.quickResponse(400, "BAD REQUEST", msg)
    } ?: return false.toSuccess()

    val response1 = schema.getString("Response", req.data)
    val response2 = schema.getString("New-Response", req.data)

    return Result.success(challenge1.first == response1 && challenge2.first == response2)
}

private fun generateChallenge(key: Encryptor): Result<Pair<String, CryptoString>> {
    val rng = SecureRandom()
    val rawBytes = ByteArray(32)
    rng.nextBytes(rawBytes)
    val challenge = Base85.encode(rawBytes)
    val encrypted = key.encrypt(challenge.toByteArray()).getOrElse { return it.toFailure() }
    return Pair(challenge, encrypted).toSuccess()
}
