package mensagod.dbcmds

import keznacl.CryptoString
import libkeycard.RandomID
import libkeycard.Timestamp
import mensagod.DBConn
import mensagod.DatabaseCorruptionException
import mensagod.MServerPath
import mensagod.NotConnectedException
import mensagod.commands.DeviceStatus

/**
 * Adds a device to a workspcae. The device's initial last login is set to when this method is
 * called because a new device is added only at certain times, such as at registration or when a
 * user logs into a workspace on a new device.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun addDevice(db: DBConn, wid: RandomID, devid: RandomID, devkey: CryptoString,
              devInfo: CryptoString, status: DeviceStatus): Throwable? {
    val now = Timestamp()
    return db.execute("""INSERT INTO iwkspc_devices(wid, devid, devkey, lastlogin, devinfo, status)
        VALUES(?,?,?,?,?,?)""", wid, devid, devkey, now, devInfo, status)
        .exceptionOrNull()
}

/**
 * addKeyInfo adds to the database an entry for a key information package. Key information packages
 * are used for key exchange among the devices in an individual workspace.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun addKeyInfo(db: DBConn, wid: RandomID, devid: RandomID, path: MServerPath) {
    db.execute("""DELETE FROM keyinfo WHERE wid=? AND devid=?""", wid, devid).getOrThrow()
    db.execute("""INSERT INTO keyinfo(wid, devid, path) VALUES(?,?,?) """, wid, devid, path)
        .getOrThrow()
}

/**
 * Returns the number of devices assigned to a workspace.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun countDevices(db: DBConn, wid: RandomID): Int {
    val rs = db.query("""SELECT COUNT(*) FROM iwkspc_devices WHERE wid=?""", wid).getOrThrow()
    if (!rs.next()) return 0
    return rs.getInt(1)
}

/**
 * Gets the encryption key for the specified device or null if not found.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun getDeviceKey(db: DBConn, wid: RandomID, devid: RandomID): CryptoString? {
    val rs = db.query("""SELECT devkey FROM iwkspc_devices WHERE wid=? AND devid=?""",
        wid, devid).getOrThrow()
    if (rs.next()) {
        val key = rs.getString("devkey")
        return CryptoString.fromString(key)
            ?: throw DatabaseCorruptionException(
                "Bad device key '$key' for device $devid in workspace $wid")
    }
    return null
}

/**
 * Returns the encrypted client information for one or more devices. If the device ID is specified,
 * only the info for the specified device is returned or an empty list if not found. If the null is
 * passed for the device ID, the device information for all devices registered to the workspace is
 * returned. When information for multiple devices is returned, it is sorted by device ID.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun getDeviceInfo(db: DBConn, wid: RandomID, devid: RandomID?): List<Pair<RandomID,CryptoString>> {
    val rs = if (devid == null) {
        db.query("""SELECT devid,devinfo FROM iwkspc_devices WHERE wid=? ORDER BY devid""", wid)
            .getOrThrow()
    } else {
        db.query("""SELECT devid,devinfo FROM iwkspc_devices WHERE wid=? AND devid=?""",
            wid, devid).getOrThrow()
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
 * exists or DeviceStatus.NotRegistered if it does not.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun getDeviceStatus(db: DBConn, wid: RandomID, devid: RandomID): DeviceStatus {
    val rs = db.query("""SELECT status FROM iwkspc_devices WHERE wid=? AND devid=?""",
        wid, devid).getOrThrow()
    if (rs.next()) {
        val stat = rs.getString("status")
        return DeviceStatus.fromString(stat)
            ?: throw DatabaseCorruptionException(
                "Bad device status '$stat' for device $devid in workspace $wid")
    }
    return DeviceStatus.NotRegistered
}

/**
 * getKeyInfo returns the path of a key information file needed for the specified device belonging
 * to the specified workspace. It returns null if the entry is not found.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun getKeyInfo(db: DBConn, wid: RandomID, devid: RandomID): MServerPath? {
    val rs = db.query("""SELECT path FROM keyinfo WHERE wid=? AND devid=?""", wid, devid)
        .getOrThrow()
    if (rs.next()) {
        val infopath = rs.getString("path")
        return MServerPath.fromString(infopath)
            ?: throw DatabaseCorruptionException(
                "Bad key info path '$infopath' for device $devid in workspace $wid")
    }
    return null
}

/**
 * Returns the time of the specified device's last login or null if it was not found.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun getLastDeviceLogin(db: DBConn, wid: RandomID, devid: RandomID): Timestamp? {
    val rs = db.query("""SELECT lastlogin FROM iwkspc_devices WHERE wid=? AND devid=?""",
        wid, devid).getOrThrow()
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
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun removeDevice(db: DBConn, wid: RandomID, devid: RandomID) {
    db.execute("""DELETE FROM iwkspc_devices WHERE wid=? AND devid=?""", wid, devid).getOrThrow()
}

/**
 * removeKeyInfo deletes a key information entry from the database
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun removeKeyInfo(db: DBConn, wid: RandomID, devid: RandomID) {
    db.execute("""DELETE FROM keyinfo WHERE wid=? AND devid=?""", wid, devid).getOrThrow()
}

/**
 * Updates a device's encrypted client info. If the device ID specified doesn't exist, this call
 * does nothing.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun updateDeviceInfo(db: DBConn, wid: RandomID, devid: RandomID, devInfo: CryptoString) {
    db.execute("""UPDATE iwkspc_devices SET devinfo=? WHERE wid=? AND devid=?""",
        devInfo, wid, devid).getOrThrow()
}

/**
 * Updates a device's status. If the device ID specified doesn't exist, this call does nothing.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun updateDeviceKey(db: DBConn, wid: RandomID, devid: RandomID, devkey: CryptoString) {
    db.execute("""UPDATE iwkspc_devices SET devkey=? WHERE wid=? AND devid=?""",
        devkey, wid, devid).getOrThrow()
}

/**
 * Updates a device's login timestamp. If the device ID specified doesn't exist, this call does
 * nothing.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun updateDeviceLogin(db: DBConn, wid: RandomID, devid: RandomID) {
    db.execute("""UPDATE iwkspc_devices SET lastlogin=? WHERE wid=? AND devid=?""",
        Timestamp(), wid, devid).getOrThrow()
}

/**
 * Updates a device's status. If the device ID specified doesn't exist, this call does nothing.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun updateDeviceStatus(db: DBConn, wid: RandomID, devid: RandomID, status: DeviceStatus) {
    db.execute("""UPDATE iwkspc_devices SET status=? WHERE wid=? AND devid=?""",
        status, wid, devid).getOrThrow()
}
