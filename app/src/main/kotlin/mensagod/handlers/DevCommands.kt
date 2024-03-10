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
        QuickResponse.sendInternalError(
            "Error authenticating client device for key update",
            state.conn
        )
        return
    }
    // We don't need to send an error message to the client because that's already taken care of in
    // dualChallengeDevice()
    if (!success) {
        ServerResponse(401, "UNAUTHORIZED")
            .sendCatching(
                state.conn, "Unable to send unauthorized message to $devid " +
                        "for ${state.wid}"
            )
        return
    }

    updateDeviceKey(DBConn(), state.wid!!, state.devid!!, newkey)?.let {
        logError("commandDevice.updateDeviceKey exception: $it")
        QuickResponse.sendInternalError("Error updating device key", state.conn)
        return
    }

    QuickResponse.sendOK("", state.conn)
}

// GETDEVICEINFO(Device-ID=null)
fun commandGetDeviceInfo(state: ClientSession) {

    if (!state.requireLogin()) return
    val devID = state.getRandomID("Device-ID", false)
    val db = DBConn()
    val infoList = getDeviceInfo(db, state.wid!!, devID).getOrElse {
        logError("commandGetDeviceInfo.getDeviceInfo exception for ${state.wid!!}: $it")
        QuickResponse.sendInternalError("Error getting device info", state.conn)
        return
    }
    if (infoList.isEmpty()) {
        QuickResponse.sendNotFound("", state.conn)
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
    if (req.action == "CANCEL") return Result.failure(CancelException())

    if (req.action != "DEVKEY") {
        QuickResponse.sendBadRequest("Session state mismatch", state.conn)
        return false.toSuccess()
    }

    val schema = Schemas.devkeyClientResponse
    schema.validate(req.data) { name, e ->
        val msg = if (e is MissingFieldException)
            "Missing required field $name"
        else
            "Bad value for field $name"
        QuickResponse.sendBadRequest(msg, state.conn)
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