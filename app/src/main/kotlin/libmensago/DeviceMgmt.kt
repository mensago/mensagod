package libmensago

import keznacl.*
import kotlinx.serialization.Serializable
import libkeycard.RandomID
import libkeycard.Timestamp

/**
 * The DeviceInfo class encapsulates identifying information for a specific device associated with
 * an identity workspace. It consists of a RandomID identifier, an asymmetric encryption keypair
 * used for login challenges and key exchange, and a
 */
@Serializable
class DeviceInfo(
    val id: RandomID, val keypair: EncryptionPair,
    var attributes: MutableMap<String, String> = mutableMapOf()
) {
    var encryptedInfo: CryptoString? = null

    /** Convenience method to update the object's attributes */
    fun collectAttributes(): Result<DeviceInfo> {
        val info = collectInfoForDevice(id, keypair.publicKey)
            .getOrElse { return it.toFailure() }
        attributes = info
        return Result.success(this)
    }

    /**
     * Method which encrypts the attributes with the provided key and stores them in the object's
     * encryptedInfo property.
     */
    fun encryptAttributes(key: Encryptor): Result<CryptoString> {
        val outStr = attributes.keys.joinToString("\r\n") { "$it=${attributes[it]}" }
        encryptedInfo = key.encrypt(outStr.encodeToByteArray())
            .getOrElse { return it.toFailure() }
        return encryptedInfo!!.toSuccess()
    }

    companion object {

        /** Creates a new set of device information for the profile */
        fun generate(): Result<DeviceInfo> {

            val id = RandomID.generate()
            val keypair = EncryptionPair.generate().getOrElse { return it.toFailure() }
            val info = collectInfoForDevice(id, keypair.publicKey)
                .getOrElse { return it.toFailure() }
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

    val out = hashMapOf(
        "Name" to Platform.getHostname(),
        "User" to Platform.getUsername().getOrElse { return it.toFailure() },
        "OS" to Platform.getOS().getOrElse { return it.toFailure() },
        "Device-ID" to devid.toString(),
        "Device-Key" to devKey.toString(),
        "Timestamp" to Timestamp().toString(),
    )
    return out.toSuccess()
}
