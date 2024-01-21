package mensagod.dbcmds

import keznacl.CryptoString
import libkeycard.RandomID
import libkeycard.Timestamp
import mensagod.DBConn
import mensagod.DatabaseCorruptionException
import mensagod.commands.DeviceStatus

/**
 * Adds a device to a workspcae. The device's initial last login is set to when this method is
 * called because a new device is added only at certain times, such as at registration or when a
 * user logs into a workspace on a new device.
 */
fun addDevice(db: DBConn, wid: RandomID, devid: RandomID, devkey: CryptoString,
              devInfo: CryptoString, status: DeviceStatus) {
    val now = Timestamp()
    db.execute("""INSERT INTO iwkspc_devices(wid, devid, devkey, lastlogin, devinfo, status
        VALUES(?,?,?,?,?,?""", wid, devid, devkey, now, devInfo, status)
}

/**
 * Returns the number of devices assigned to a workspace.
 */
fun countDevices(db: DBConn, wid: RandomID): Int {
    val rs = db.query("""SELECT COUNT(*) FROM iwkspc_devices WHERE wid=?""", wid)
    if (!rs.next()) return 0
    return rs.getInt(1)
}

/**
 * Returns the encrypted client information for one or more devices. If the device ID is specified,
 * only the info for the specified device is returned or an empty list if not found. If the null is
 * passed for the device ID, the device information for all devices registered to the workspace is
 * returned.
 */
fun getDeviceInfo(db: DBConn, wid: RandomID, devid: RandomID?): List<Pair<RandomID,CryptoString>> {
    val rs = if (devid == null) {
        db.query("""SELECT devid,devinfo FROM iwkspace_devices WHERE wid=?""", wid)
    } else {
        db.query("""SELECT devid,devinfo FROM iwkspace_devices WHERE wid=? AND devid=?""",
            wid, devid)
    }

    val out = mutableListOf<Pair<RandomID,CryptoString>>()
    while (rs.next()) {
        val dev = RandomID.fromString(rs.getString("devid"))
            ?: throw DatabaseCorruptionException("Bad device ID in wid $wid")
        val info = CryptoString.fromString(rs.getString("devinfo"))
            ?: throw DatabaseCorruptionException("Bad device info for wid $wid")
        out.add(Pair(dev,info))
    }
    return out
}

/**
 * Checks if a particular device ID has been added to a workspace and returns its status if it
 * exists or null if it does not.
 */
fun getDeviceStatus(db: DBConn, wid: RandomID, devid: RandomID): DeviceStatus? {
    val rs = db.query("""SELECT status FROM iwkspc_devices WHERE wid=? AND devid=?""",
        wid, devid)
    if (rs.next()) {
        val stat = rs.getString("status")
        return DeviceStatus.fromString(stat)
            ?: throw DatabaseCorruptionException(
                "Bad device status '$stat' for device $devid in workspace $wid")
    }
    return null
}

/**
 * Returns the time of the specified device's last login or null if it was not found.
 */
fun getLastDeviceLogin(db: DBConn, wid: RandomID, devid: RandomID): Timestamp? {
    val rs = db.query("""SELECT lastlogin FROM iwkspc_devices WHERE wid=? AND devid=?""",
        wid, devid)
    if (rs.next()) {
        val lastlogin = rs.getString("lastlogin")
        return Timestamp.fromString(lastlogin)
            ?: throw DatabaseCorruptionException(
                "Bad device timestamp '$lastlogin' for device $devid in workspace $wid")
    }
    return null
}

/**
 * Removes a device from a workspace.
 */
fun removeDevice(db: DBConn, wid: RandomID, devid: RandomID) {
    db.execute("""DELETE FROM iwkspc_devices WHERE wid=? AND devid=?""", wid, devid)
}

/**
 * Updates a device's encrypted client info. If the device ID specified doesn't exist, this call
 * does nothing.
 */
fun updateDeviceInfo(db: DBConn, wid: RandomID, devid: RandomID, devInfo: CryptoString) {
    db.execute("""UDPATE SET devinfo=? FROM iwkspc_devices WHERE wid=? AND devid=?""",
        devInfo, wid, devid)
}

/**
 * Updates a device's status. If the device ID specified doesn't exist, this call does nothing.
 */
fun updateDeviceKey(db: DBConn, wid: RandomID, devid: RandomID, devkey: CryptoString) {
    db.execute("""UDPATE SET devkey=? FROM iwkspc_devices WHERE wid=? AND devid=?""",
        devkey, wid, devid)
}

/**
 * Updates a device's login timestamp. If the device ID specified doesn't exist, this call does
 * nothing.
 */
fun updateDeviceLogin(db: DBConn, wid: RandomID, devid: RandomID) {
    db.execute("""UDPATE SET lastlogin=? FROM iwkspc_devices WHERE wid=? AND devid=?""",
        Timestamp(), wid, devid)
}

/**
 * Updates a device's status. If the device ID specified doesn't exist, this call does nothing.
 */
fun updateDeviceStatus(db: DBConn, wid: RandomID, devid: RandomID, status: DeviceStatus) {
    db.execute("""UDPATE SET status=? FROM iwkspc_devices WHERE wid=? AND devid=?""",
        status, wid, devid)
}
