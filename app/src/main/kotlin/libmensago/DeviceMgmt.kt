package libmensago

import keznacl.CryptoString
import keznacl.EncryptionPair
import keznacl.Encryptor
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import libkeycard.RandomID
import libkeycard.Timestamp

/**
 * The DeviceInfo class encapsulates identifying information for a specific device associated with
 * an identity workspace. It consists of a RandomID identifier, an asymmetric encryption keypair
 * used for login challenges and key exchange, and a
 */
class DeviceInfo(
    val id: RandomID, val keypair: EncryptionPair,
    var attributes: MutableMap<String, String> = mutableMapOf()
) {
    var encryptedInfo: CryptoString? = null

    /** Convenience method to update the object's attributes */
    fun collectAttributes(): Result<DeviceInfo> {
        val info = collectInfoForDevice(id, keypair.publicKey)
            .getOrElse { return Result.failure(it) }
        attributes = info
        return Result.success(this)
    }

    /**
     * Method which encrypts the attributes with the provided key and stores them in the object's
     * encryptedInfo property.
     */
    fun encryptAttributes(key: Encryptor): Result<DeviceInfo> {
        val outJSON = try {
            Json.encodeToString(attributes)
        } catch (e: Exception) {
            return Result.failure(e)
        }
        encryptedInfo = key.encrypt(outJSON.encodeToByteArray())
            .getOrElse { return Result.failure(it) }
        return Result.success(this)
    }

    companion object {

        /** Creates a new set of device information for the profile */
        fun generate(): Result<DeviceInfo> {

            val id = RandomID.generate()
            val keypair = EncryptionPair.generate().getOrElse { return Result.failure(it) }
            val info = collectInfoForDevice(id, keypair.publicKey)
                .getOrElse { return Result.failure(it) }
            return Result.success(DeviceInfo(id, keypair, info))
        }
    }
}

/**
 * collectInfoForDevice() returns a map of information about a device that is helpful for users
 * to identify the device, including the hostname, a timestamp of when the information was obtained,
 * etc.
 */
fun collectInfoForDevice(
    devid: RandomID,
    devKey: CryptoString
): Result<MutableMap<String, String>> {

    // TODO: Finish implementing collectInfoForDevice()

    val out = hashMapOf(
        "Name" to Platform.getHostname().getOrElse { return Result.failure(it) },
        "User" to Platform.getUsername().getOrElse { return Result.failure(it) },
        "OS" to Platform.getOS().getOrElse { return Result.failure(it) },
        "Device-ID" to devid.toString(),
        "Device-Key" to devKey.toString(),
        "Timestamp" to Timestamp().toString(),
    )
    return Result.success(out)
}
