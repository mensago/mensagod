package mensagod.commands

import keznacl.CryptoString
import libkeycard.RandomID
import mensagod.*
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import java.net.InetAddress
import java.net.Socket

class LoginCmdTest {
    @Test
    fun preregTest() {
        setupTest("commands.preregTest")
        val config = ServerConfig.load()
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!

        // Test Case #1: Supply no data. Expect WID, Domain, and reg code
        var regUser = RandomID.generate()
        CommandTest("prereg.1",
            SessionState(ClientRequest("PREREG", mutableMapOf()), adminWID,
                LoginState.LoggedIn), ::commandPreregister) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            assertEquals(200, response.code)
            assertNull(response.data["User-ID"])
            assertEquals(gServerDomain.toString(), response.data["Domain"])
            regUser = RandomID.fromString(response.data["Workspace-ID"])!!
            assertEquals(config.getInteger("security.diceware_wordcount"),
                response.data["Reg-Code"]?.split(" ")?.size)
        }.run()

        // Test Case #2: Supply all data.
        CommandTest("prereg.2",
            SessionState(ClientRequest("PREREG", mutableMapOf(
                "User-ID" to "csimons",
                "Workspace-ID" to "a2950671-99cd-4ad5-8d6c-3efdd125a6d2",
                "Domain" to "example.com",
            )), adminWID, LoginState.LoggedIn), ::commandPreregister) { port ->
                val socket = Socket(InetAddress.getByName("localhost"), port)
                val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

                assertEquals(200, response.code)
                assertEquals("csimons", response.data["User-ID"])
                assertEquals("example.com", response.data["Domain"])
                assertEquals("a2950671-99cd-4ad5-8d6c-3efdd125a6d2",
                    response.data["Workspace-ID"])
                assertEquals(config.getInteger("security.diceware_wordcount"),
                    response.data["Reg-Code"]?.split(" ")?.size)
        }.run()

        // Test Case #3: Try to preregister an existing user
        CommandTest("prereg.3",
            SessionState(ClientRequest("PREREG", mutableMapOf(
                "Workspace-ID" to regUser.toString(),
                "Domain" to gServerDomain.toString(),
            )), adminWID, LoginState.LoggedIn), ::commandPreregister) { port ->
                val socket = Socket(InetAddress.getByName("localhost"), port)
                val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

                assertEquals(408, response.code)
        }.run()
    }

    @Test
    fun regCodeTest() {
        setupTest("commands.regCodeTest")

        val devid = RandomID.fromString(ADMIN_PROFILE_DATA["devid"])!!
        val devkey = CryptoString.fromString(ADMIN_PROFILE_DATA["device.public"]!!)

        // Test Case #1: Regcode a user
        val db = DBConn()
        val regInfo = preregUser(db, "csimons")
        CommandTest("regcode.1",
            SessionState(ClientRequest("REGCODE", mutableMapOf(
                "Reg-Code" to regInfo["Reg-Code"]!!,
                "User-ID" to "csimons",
                "Password-Hash" to "this is a pretty terrible password",
                "Password-Algorithm" to "cleartext",
                "Device-ID" to devid.toString(),
                "Device-Key" to devkey.toString(),
                "Device-Info" to "XSALSA20:SomethingIDontCare"
            )), null, LoginState.NoSession), ::commandRegCode) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            assertReturnCode(201, response)
            assertEquals("csimons", response.data["User-ID"])
            assertEquals(gServerDomain.toString(), response.data["Domain"])
        }.run()
    }
}