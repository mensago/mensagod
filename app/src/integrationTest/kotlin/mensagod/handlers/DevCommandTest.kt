package mensagod.handlers

import keznacl.CryptoString
import libkeycard.RandomID
import libmensago.ClientRequest
import libmensago.ServerResponse
import mensagod.DBConn
import mensagod.LoginState
import mensagod.SessionState
import mensagod.dbcmds.addDevice
import mensagod.dbcmds.updateDeviceStatus
import org.junit.jupiter.api.Test
import testsupport.ADMIN_PROFILE_DATA
import testsupport.assertReturnCode
import testsupport.setupTest
import java.net.InetAddress
import java.net.Socket

class DevCommandTest {

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
}