package mensagod.dbcmds

import keznacl.CryptoString
import libkeycard.RandomID
import mensagod.commands.DeviceStatus

fun addDevice(wid: RandomID, devid: RandomID, devkey: CryptoString, devInfo: CryptoString,
              status: DeviceStatus) {
    TODO("Implement dbcmds::addDevice($wid,$devid,$devkey,$devInfo,$status")
}

