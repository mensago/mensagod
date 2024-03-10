package mensagod.handlers

import keznacl.CryptoString
import keznacl.EncryptionPair
import libkeycard.RandomID
import libmensago.ClientRequest
import libmensago.ServerResponse
import mensagod.DBConn
import mensagod.LoginState
import mensagod.SessionState
import mensagod.dbcmds.addDevice
import mensagod.dbcmds.updateDeviceStatus
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import testsupport.ADMIN_PROFILE_DATA
import testsupport.assertReturnCode
import testsupport.setupTest
import java.net.InetAddress
import java.net.Socket
import java.time.Instant

class DevCommandTest {

    @Test
    fun devKeyTest() {
        setupTest("handlers.devKey")
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        val devid = RandomID.fromString(ADMIN_PROFILE_DATA["devid"])!!
        val oldPair = EncryptionPair.fromStrings(
            ADMIN_PROFILE_DATA["device.public"]!!,
            ADMIN_PROFILE_DATA["device.private"]!!
        ).getOrThrow()
        val newPair = EncryptionPair.fromStrings(
            "CURVE25519:wv-Q}5&La(d-vZ?Mq@<|ad&e73)eaP%NAh{HDUo;",
            "CURVE25519:X5@Vi_4_JZ_mOPeNWKY5hOIi&1ddz#C9K`L=_&M^"
        ).getOrThrow()

        // Case #1: Successful login
        CommandTest(
            "devkey.1",
            SessionState(
                ClientRequest(
                    "DEVKEY", mutableMapOf(
                        "Device-ID" to devid.toString(),
                        "Old-Key" to oldPair.pubKey.toString(),
                        "New-Key" to newPair.pubKey.toString(),
                    )
                ),
                adminWID, LoginState.LoggedIn, devid,
            ), ::commandDevKey
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            var response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(100)

            assert(
                response.checkFields(
                    listOf(
                        Pair("Challenge", true),
                        Pair("New-Challenge", true)
                    )
                )
            )
            val oldChallenge = CryptoString.fromString(response.data["Challenge"]!!)!!
            val newChallenge = CryptoString.fromString(response.data["New-Challenge"]!!)!!
            val oldResponse = oldPair.decryptString(oldChallenge).getOrThrow()
            val newResponse = newPair.decryptString(newChallenge).getOrThrow()

            val req = ClientRequest(
                "DEVKEY", mutableMapOf(
                    "Device-ID" to devid.toString(),
                    "Response" to oldResponse,
                    "New-Response" to newResponse
                )
            )
            req.send(socket.getOutputStream())
            response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(200)

            val db = DBConn()
            val rs = db.query(
                """SELECT devkey FROM iwkspc_devices WHERE wid=? AND devid=?""",
                adminWID, devid
            ).getOrThrow()
            assert(rs.next())
            assertEquals(newPair.pubKey.toString(), rs.getString("devkey"))
        }.run()

        // Case #2: Device ID mismatch
        CommandTest(
            "devkey.2",
            SessionState(
                ClientRequest(
                    "DEVKEY", mutableMapOf(
                        "Device-ID" to devid.toString(),
                        "Old-Key" to oldPair.pubKey.toString(),
                        "New-Key" to newPair.pubKey.toString(),
                    )
                ), adminWID, LoginState.LoggedIn
            ), ::commandDevKey
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(403)
        }.run()

        // Case #3: Challenge-Response failure
        CommandTest(
            "devkey.3",
            SessionState(
                ClientRequest(
                    "DEVKEY", mutableMapOf(
                        "Device-ID" to devid.toString(),
                        "Old-Key" to oldPair.pubKey.toString(),
                        "New-Key" to newPair.pubKey.toString(),
                    )
                ),
                adminWID, LoginState.LoggedIn, devid,
            ), ::commandDevKey
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            var response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(100)

            val req = ClientRequest(
                "DEVKEY", mutableMapOf(
                    "Device-ID" to devid.toString(),
                    "Response" to "foo",
                    "New-Response" to "bar",
                )
            )
            req.send(socket.getOutputStream())
            response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(401)
        }.run()
    }

    @Test
    fun getDeviceInfoTest() {
        setupTest("handlers.getDeviceInfo")
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        val devid = RandomID.fromString(ADMIN_PROFILE_DATA["devid"])!!
        val devid2 = RandomID.fromString("61ae62b5-28f0-4b44-9eb4-8f81b761ad18")!!
        val devPair2 = EncryptionPair.fromStrings(
            "CURVE25519:wv-Q}5&La(d-vZ?Mq@<|ad&e73)eaP%NAh{HDUo;",
            "CURVE25519:X5@Vi_4_JZ_mOPeNWKY5hOIi&1ddz#C9K`L=_&M^"
        ).getOrThrow()
        val fakeInfo = CryptoString.fromString("XSALSA20:myfakedevInfoYAY")!!

        val db = DBConn()
        db.execute(
            "INSERT INTO iwkspc_devices(wid,devid,devkey,devinfo,lastlogin,status) " +
                    "VALUES(?,?,?,?,?,?)",
            adminWID,
            devid2,
            devPair2.pubKey,
            fakeInfo,
            Instant.now(),
            "registered"
        ).getOrThrow()

        // Case #1: Successful get for 1 device
        CommandTest(
            "getDeviceInfo.1",
            SessionState(
                ClientRequest(
                    "GETDEVICEINFO", mutableMapOf(
                        "Device-ID" to ADMIN_PROFILE_DATA["devid"]!!,
                    )
                ), adminWID, LoginState.LoggedIn
            ), ::commandGetDeviceInfo
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(200)
            assert(response.data.containsKey("Device-Info"))

            val rs = db.query(
                """SELECT devid,devinfo FROM iwkspc_devices WHERE wid=? AND devid=?""",
                adminWID,
                devid
            ).getOrThrow()
            assert(rs.next())
            assertEquals(devid.toString(), rs.getString("devid"))
            assert(rs.getString("devinfo").isNotEmpty())
        }.run()

        // Case #2: Successful get for multiple devices
        CommandTest(
            "getDeviceInfo.2",
            SessionState(
                ClientRequest(
                    "GETDEVICEINFO", mutableMapOf()
                ), adminWID, LoginState.LoggedIn
            ), ::commandGetDeviceInfo
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(200)
            assert(response.data.containsKey("Devices"))

            val devices = response.data["Devices"]!!.split(",")
            assertEquals(devid.toString(), devices[0])
            assertEquals(devid2.toString(), devices[1])

            assertEquals("XSALSA20:ABCDEFG1234567890", response.data[devid.toString()])
            assertEquals(fakeInfo.toString(), response.data[devid2.toString()])

        }.run()

        // Case #3: Device not found
        CommandTest(
            "getDeviceInfo.3",
            SessionState(
                ClientRequest(
                    "GETDEVICEINFO", mutableMapOf(
                        "Device-ID" to "4171c1e9-fab2-47bf-b383-f2342282b301",
                    )
                ), adminWID, LoginState.LoggedIn
            ), ::commandGetDeviceInfo
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(404)
        }.run()
    }

    @Test
    fun keyPkgTest() {
        setupTest("handlers.keyPkgTest")
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        val devid = RandomID.fromString("61ae62b5-28f0-4b44-9eb4-8f81b761ad18")!!
        val fakeKey = CryptoString.fromString("XSALSA20:myfakedevkeyLOL")!!
        val fakeInfo = CryptoString.fromString("XSALSA20:myfakedevInfoYAY")!!

        val db = DBConn()
        addDevice(db, adminWID, devid, fakeKey, fakeInfo, DeviceStatus.Pending)?.let { throw it }

        // Test Case #1: Successful execution
        CommandTest(
            "keypkg.1",
            SessionState(
                ClientRequest(
                    "KEYPKG", mutableMapOf(
                        "Device-ID" to devid.toString(),
                        "Key-Info" to "XSALSA20:abcdefg1234567890",
                    )
                ), adminWID, LoginState.LoggedIn
            ), ::commandKeyPkg
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(200)
        }.run()

        // Test Case #2: Already approved
        CommandTest(
            "keypkg.2",
            SessionState(
                ClientRequest(
                    "KEYPKG", mutableMapOf(
                        "Device-ID" to devid.toString(),
                        "Key-Info" to "XSALSA20:abcdefg1234567890",
                    )
                ), adminWID, LoginState.LoggedIn
            ), ::commandKeyPkg
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(203)
        }.run()

        // Test Case #3: Already registered
        updateDeviceStatus(db, adminWID, devid, DeviceStatus.Registered)?.let { throw it }
        CommandTest(
            "keypkg.3",
            SessionState(
                ClientRequest(
                    "KEYPKG", mutableMapOf(
                        "Device-ID" to devid.toString(),
                        "Key-Info" to "XSALSA20:abcdefg1234567890",
                    )
                ), adminWID, LoginState.LoggedIn
            ), ::commandKeyPkg
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(201)
        }.run()

        // Test Case #4: Error for a blocked device
        updateDeviceStatus(db, adminWID, devid, DeviceStatus.Blocked)?.let { throw it }
        CommandTest(
            "keypkg.4",
            SessionState(
                ClientRequest(
                    "KEYPKG", mutableMapOf(
                        "Device-ID" to devid.toString(),
                        "Key-Info" to "XSALSA20:abcdefg1234567890",
                    )
                ), adminWID, LoginState.LoggedIn
            ), ::commandKeyPkg
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(403)
        }.run()
    }

    @Test
    fun removeDeviceTest() {
        setupTest("handlers.removeDevice")
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        val devid = RandomID.fromString(ADMIN_PROFILE_DATA["devid"])!!
        val devid2 = RandomID.fromString("61ae62b5-28f0-4b44-9eb4-8f81b761ad18")!!
        val devPair2 = EncryptionPair.fromStrings(
            "CURVE25519:wv-Q}5&La(d-vZ?Mq@<|ad&e73)eaP%NAh{HDUo;",
            "CURVE25519:X5@Vi_4_JZ_mOPeNWKY5hOIi&1ddz#C9K`L=_&M^"
        ).getOrThrow()
        val fakeInfo = CryptoString.fromString("XSALSA20:myfakedevInfoYAY")!!

        val db = DBConn()
        db.execute(
            "INSERT INTO iwkspc_devices(wid,devid,devkey,devinfo,lastlogin,status) " +
                    "VALUES(?,?,?,?,?,?)",
            adminWID,
            devid2,
            devPair2.pubKey,
            fakeInfo,
            Instant.now(),
            "registered"
        ).getOrThrow()

        // Case #1: Success
        CommandTest(
            "removedevice.1",
            SessionState(
                ClientRequest(
                    "REMOVEDEVICE", mutableMapOf(
                        "Device-ID" to devid2.toString(),
                    )
                ),
                adminWID, LoginState.LoggedIn, devid,
            ), ::commandRemoveDevice
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(200)

            val rs = db.query(
                """SELECT devid FROM iwkspc_devices WHERE wid=? AND devid=?""",
                adminWID, devid2
            ).getOrThrow()
            assert(!rs.next())
        }.run()

        // Because of how the test itself is set up, we can't test connection termination if the
        // current device is removed. That will have to be tested via a client integration test
    }

    @Test
    fun setDeviceInfoTest() {
        setupTest("handlers.setDeviceInfo")
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        val devid = RandomID.fromString(ADMIN_PROFILE_DATA["devid"])!!
        val fakeInfo = "XSALSA20:myNewFakeInfoWOOT"

        // Case #1: Success
        CommandTest(
            "setdeviceinfo.1",
            SessionState(
                ClientRequest("SETDEVICEINFO", mutableMapOf("Device-Info" to fakeInfo)),
                adminWID, LoginState.LoggedIn, devid,
            ), ::commandSetDeviceInfo
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(200)

            val rs = DBConn().query(
                """SELECT devinfo FROM iwkspc_devices WHERE wid=? AND devid=?""",
                adminWID, devid
            ).getOrThrow()
            assert(rs.next())
            assertEquals(fakeInfo, rs.getString("devinfo"))
        }.run()

        // This call only really needs 1 test because it's so simple and shouldn't fail unless
        // there is a problem with the database itself.
    }
}
