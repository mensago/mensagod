package mensagod.dbcmds

import keznacl.CryptoString
import libkeycard.RandomID
import libmensago.MServerPath
import mensagod.DBConn
import mensagod.ServerConfig
import mensagod.handlers.DeviceStatus
import mensagod.resetDB
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import testsupport.ADMIN_PROFILE_DATA
import testsupport.initDB

class DBDeviceCmdTest {

    @Test
    fun multiTest() {
        // Most of these methods depend on one another, so just make a bigger test case which hits
        // a bunch of them. Most of them have super simple implementations, so this isn't such
        // a bad thing.

        // Methods tested:
        // addDevice
        // countDevices
        // getDeviceStatus
        // getLastDeviceLogin
        // removeDevice

        val config = ServerConfig.load().getOrThrow()
        resetDB(config).getOrThrow()
        DBConn.initialize(config)?.let { throw it }
        val db = DBConn().connect().getOrThrow()
        initDB(db.getConnection()!!)

        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        val devid = RandomID.fromString("c41cb142-9742-4b38-b250-7d61b22beb31")!!
        val badID = RandomID.fromString("89b7f0cc-9dea-412a-b9da-f3a4f131bd78")!!
        assertEquals(0, countDevices(db, adminWID).getOrThrow())

        val devKey = CryptoString.fromString(
            "CURVE25519:nSRso=K(WF{P+4x5S*5?Da-rseY-^>S8VN#v+)IN"
        )!!
        val fakeInfo = CryptoString.fromString("AES256:ABCDEFG123456789")!!
        addDevice(db, adminWID, devid, devKey, fakeInfo, DeviceStatus.Pending)?.let { throw it }
        assertEquals(1, countDevices(db, adminWID).getOrThrow())

        val devid2 = RandomID.fromString("557688c4-8324-4577-ad8b-2dc6fed79567")!!
        addDevice(db, adminWID, devid2, devKey, fakeInfo, DeviceStatus.Registered)?.let { throw it }
        assertEquals(2, countDevices(db, adminWID).getOrThrow())

        assertEquals(DeviceStatus.Pending, getDeviceStatus(db, adminWID, devid).getOrThrow())
        assertEquals(DeviceStatus.NotRegistered, getDeviceStatus(db, adminWID, badID).getOrThrow())

        assertNotNull(getLastDeviceLogin(db, adminWID, devid).getOrThrow())
        assertNull(getLastDeviceLogin(db, adminWID, badID).getOrThrow())
        val firstlogin = getLastDeviceLogin(db, adminWID, devid).getOrThrow()!!
        Thread.sleep(1000)
        updateDeviceLogin(db, adminWID, devid)?.let { throw it }
        val secondlogin = getLastDeviceLogin(db, adminWID, devid).getOrThrow()!!
        assert(secondlogin.toString() > firstlogin.toString())

        removeDevice(db, adminWID, devid2)?.let { throw it }
        assertEquals(1, countDevices(db, adminWID).getOrThrow())
    }

    @Test
    fun multitest2() {
        // This one tests all the methods that the first case didn't get, mostly device info stuff.

        val config = ServerConfig.load().getOrThrow()
        resetDB(config).getOrThrow()
        DBConn.initialize(config)?.let { throw it }
        val db = DBConn().connect().getOrThrow()
        initDB(db.getConnection()!!)

        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        val devid = RandomID.fromString("1e9538b4-880a-4792-a8b9-efe0382d1cd5")!!
        val badID = RandomID.fromString("eb859f7e-8ed3-4859-aae3-e969de8011db")!!

        assertEquals(0, getDeviceInfo(db, adminWID, null).getOrThrow().size)

        val devKey = CryptoString.fromString(
            "CURVE25519:nSRso=K(WF{P+4x5S*5?Da-rseY-^>S8VN#v+)IN"
        )!!
        val fakeInfo = CryptoString.fromString("AES256:ABCDEFG123456789")!!
        addDevice(db, adminWID, devid, devKey, fakeInfo, DeviceStatus.Pending)?.let { throw it }

        val devid2 = RandomID.fromString("557688c4-8324-4577-ad8b-2dc6fed79567")!!
        val fakeInfo2 = CryptoString.fromString("XSALSA20:ABCDEFG123456789")!!
        addDevice(db, adminWID, devid2, devKey, fakeInfo2, DeviceStatus.Registered)
            ?.let { throw it }

        val infoList = getDeviceInfo(db, adminWID, devid).getOrThrow()
        assertEquals(1, infoList.size)
        assertEquals(devid, infoList[0].first)
        assertEquals(fakeInfo, infoList[0].second)

        assertEquals(0, getDeviceInfo(db, adminWID, badID).getOrThrow().size)

        val infoList2 = getDeviceInfo(db, adminWID, null).getOrThrow()
        assertEquals(2, infoList2.size)
        assertEquals(devid2, infoList2[1].first)
        assertEquals(fakeInfo2, infoList2[1].second)

        updateDeviceInfo(db, adminWID, devid, fakeInfo2)?.let { throw it }
        assertEquals(fakeInfo2, getDeviceInfo(db, adminWID, devid).getOrThrow()[0].second)

        val devKey2 = CryptoString.fromString(
            "CURVE25519:mO?WWA-k2B2O|Z%fA`~s3^\$iiN{5R->#jxO@cy6{"
        )!!
        updateDeviceKey(db, adminWID, devid, devKey2)?.let { throw it }
        assertEquals(devKey2, getDeviceKey(db, adminWID, devid).getOrThrow())
        assertNull(getDeviceKey(db, adminWID, badID).getOrThrow())

        updateDeviceStatus(db, adminWID, devid, DeviceStatus.Registered)?.let { throw it }
        assertEquals(DeviceStatus.Registered, getDeviceStatus(db, adminWID, devid).getOrThrow())
        assertEquals(DeviceStatus.NotRegistered, getDeviceStatus(db, adminWID, badID).getOrThrow())
    }

    @Test
    fun keyInfoTest() {
        val config = ServerConfig.load().getOrThrow()
        resetDB(config).getOrThrow()
        DBConn.initialize(config)?.let { throw it }
        val db = DBConn().connect().getOrThrow()
        initDB(db.getConnection()!!)

        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        val devid = RandomID.fromString("c41cb142-9742-4b38-b250-7d61b22beb31")!!
        val testPath = MServerPath("/ keys $adminWID $devid")

        assertNull(getKeyInfo(db, adminWID, devid).getOrThrow())
        addKeyInfo(db, adminWID, devid, testPath)?.let { throw it }

        val rs = db.query(
            """SELECT wid,devid,path FROM keyinfo WHERE wid=? AND devid=?""",
            adminWID, devid
        ).getOrThrow()
        assert(rs.next())
        assertEquals(adminWID.toString(), rs.getString("wid"))
        assertEquals(devid.toString(), rs.getString("devid"))
        assertEquals(testPath.toString(), rs.getString("path"))

        val infopath = getKeyInfo(db, adminWID, devid).getOrThrow()!!
        assertEquals(testPath.toString(), infopath.toString())

        removeKeyInfo(db, adminWID, devid)
        assertNull(getKeyInfo(db, adminWID, devid).getOrThrow())
    }
}