package mensagod.dbcmds

import keznacl.CryptoString
import libkeycard.RandomID
import mensagod.*
import mensagod.commands.DeviceStatus
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

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
        DBConn.initialize(config)
        val db = DBConn().connect()
        initDB(db.getConnection()!!)

        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        val devid = RandomID.fromString("c41cb142-9742-4b38-b250-7d61b22beb31")!!
        val badID = RandomID.fromString("89b7f0cc-9dea-412a-b9da-f3a4f131bd78")!!
        assertEquals(0, countDevices(db, adminWID))

        val devKey = CryptoString.fromString(
            "CURVE25519:nSRso=K(WF{P+4x5S*5?Da-rseY-^>S8VN#v+)IN")!!
        val fakeInfo = CryptoString.fromString("AES256:ABCDEFG123456789")!!
        addDevice(db, adminWID, devid, devKey, fakeInfo, DeviceStatus.Pending)
        assertEquals(1, countDevices(db, adminWID))

        val devid2 = RandomID.fromString("557688c4-8324-4577-ad8b-2dc6fed79567")!!
        addDevice(db, adminWID, devid2, devKey, fakeInfo, DeviceStatus.Registered)
        assertEquals(2, countDevices(db, adminWID))

        assertEquals(DeviceStatus.Pending, getDeviceStatus(db, adminWID, devid))
        assertEquals(DeviceStatus.NotRegistered, getDeviceStatus(db, adminWID, badID))

        assertNotNull(getLastDeviceLogin(db, adminWID, devid))
        assertNull(getLastDeviceLogin(db, adminWID, badID))
        val firstlogin = getLastDeviceLogin(db, adminWID, devid)!!
        Thread.sleep(1000)
        updateDeviceLogin(db, adminWID, devid)
        val secondlogin = getLastDeviceLogin(db, adminWID, devid)!!
        assert(secondlogin.toString() > firstlogin.toString())

        removeDevice(db, adminWID, devid2)
        assertEquals(1, countDevices(db, adminWID))
    }

    @Test
    fun multitest2() {
        // This one tests all the methods that the first case didn't get, mostly device info stuff.

        val config = ServerConfig.load().getOrThrow()
        resetDB(config).getOrThrow()
        DBConn.initialize(config)
        val db = DBConn().connect()
        initDB(db.getConnection()!!)

        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        val devid = RandomID.fromString("1e9538b4-880a-4792-a8b9-efe0382d1cd5")!!
        val badID = RandomID.fromString("eb859f7e-8ed3-4859-aae3-e969de8011db")!!

        assertEquals(0, getDeviceInfo(db, adminWID, null).size)

        val devKey = CryptoString.fromString(
            "CURVE25519:nSRso=K(WF{P+4x5S*5?Da-rseY-^>S8VN#v+)IN")!!
        val fakeInfo = CryptoString.fromString("AES256:ABCDEFG123456789")!!
        addDevice(db, adminWID, devid, devKey, fakeInfo, DeviceStatus.Pending)

        val devid2 = RandomID.fromString("557688c4-8324-4577-ad8b-2dc6fed79567")!!
        val fakeInfo2 = CryptoString.fromString("XSALSA20:ABCDEFG123456789")!!
        addDevice(db, adminWID, devid2, devKey, fakeInfo2, DeviceStatus.Registered)

        val infoList = getDeviceInfo(db, adminWID, devid)
        assertEquals(1, infoList.size)
        assertEquals(devid, infoList[0].first)
        assertEquals(fakeInfo, infoList[0].second)

        assertEquals(0, getDeviceInfo(db, adminWID, badID).size)

        val infoList2 = getDeviceInfo(db, adminWID, null)
        assertEquals(2, infoList2.size)
        assertEquals(devid2, infoList2[1].first)
        assertEquals(fakeInfo2, infoList2[1].second)

        updateDeviceInfo(db, adminWID, devid, fakeInfo2)
        assertEquals(fakeInfo2, getDeviceInfo(db, adminWID, devid)[0].second)

        val devKey2 = CryptoString.fromString(
            "CURVE25519:mO?WWA-k2B2O|Z%fA`~s3^\$iiN{5R->#jxO@cy6{")!!
        updateDeviceKey(db, adminWID, devid, devKey2)
        assertEquals(devKey2, getDeviceKey(db, adminWID, devid))
        assertNull(getDeviceKey(db, adminWID, badID))

        updateDeviceStatus(db, adminWID, devid, DeviceStatus.Registered)
        assertEquals(DeviceStatus.Registered, getDeviceStatus(db, adminWID, devid))
        assertEquals(DeviceStatus.NotRegistered, getDeviceStatus(db, adminWID, badID))
    }

    @Test
    fun keyInfoTest() {
        val config = ServerConfig.load().getOrThrow()
        resetDB(config).getOrThrow()
        DBConn.initialize(config)
        val db = DBConn().connect()
        initDB(db.getConnection()!!)

        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        val devid = RandomID.fromString("c41cb142-9742-4b38-b250-7d61b22beb31")!!
        val testPath = MServerPath("/ keys $adminWID $devid")

        assertNull(getKeyInfo(db, adminWID, devid))
        addKeyInfo(db, adminWID, devid, testPath)

        val rs = db.query("""SELECT wid,devid,path FROM keyinfo WHERE wid=? AND devid=?""",
            adminWID, devid)
        assert(rs.next())
        assertEquals(adminWID.toString(), rs.getString("wid"))
        assertEquals(devid.toString(), rs.getString("devid"))
        assertEquals(testPath.toString(), rs.getString("path"))

        val infopath = getKeyInfo(db, adminWID, devid)!!
        assertEquals(testPath.toString(), infopath.toString())

        removeKeyInfo(db, adminWID, devid)
        assertNull(getKeyInfo(db, adminWID, devid))
    }
}