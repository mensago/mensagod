package mensagod.handlers

import keznacl.CryptoString
import libkeycard.RandomID
import libmensago.ClientRequest
import libmensago.ServerResponse
import mensagod.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import testsupport.ADMIN_PROFILE_DATA
import testsupport.assertReturnCode
import testsupport.preregUser
import testsupport.setupTest
import java.net.InetAddress
import java.net.Socket

class RegCmdTest {
    @Test
    fun preregTest() {
        setupTest("handlers.prereg")
        val config = ServerConfig.load().getOrThrow()
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!

        // Test Case #1: Supply no data. Expect WID, Domain, and reg code
        var regUser = RandomID.generate()
        CommandTest(
            "prereg.1",
            SessionState(
                ClientRequest("PREREG", mutableMapOf()), adminWID,
                LoginState.LoggedIn
            ), ::commandPreregister
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            assertEquals(200, response.code)
            assertNull(response.data["User-ID"])
            assertEquals(gServerDomain.toString(), response.data["Domain"])
            regUser = RandomID.fromString(response.data["Workspace-ID"])!!
            assertEquals(
                config.getInteger("security.diceware_wordcount"),
                response.data["Reg-Code"]?.split(" ")?.size
            )
        }.run()

        // Test Case #2: Supply all data.
        CommandTest(
            "prereg.2",
            SessionState(
                ClientRequest(
                    "PREREG", mutableMapOf(
                        "User-ID" to "csimons",
                        "Workspace-ID" to "a2950671-99cd-4ad5-8d6c-3efdd125a6d2",
                        "Domain" to "example.com",
                    )
                ), adminWID, LoginState.LoggedIn
            ), ::commandPreregister
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            assertEquals(200, response.code)
            assertEquals("csimons", response.data["User-ID"])
            assertEquals("example.com", response.data["Domain"])
            assertEquals(
                "a2950671-99cd-4ad5-8d6c-3efdd125a6d2",
                response.data["Workspace-ID"]
            )
            assertEquals(
                config.getInteger("security.diceware_wordcount"),
                response.data["Reg-Code"]?.split(" ")?.size
            )
        }.run()

        // Test Case #3: Try to preregister an existing user
        CommandTest(
            "prereg.3",
            SessionState(
                ClientRequest(
                    "PREREG", mutableMapOf(
                        "Workspace-ID" to regUser.toString(),
                        "Domain" to gServerDomain.toString(),
                    )
                ), adminWID, LoginState.LoggedIn
            ), ::commandPreregister
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            assertEquals(408, response.code)
        }.run()
    }

    @Test
    fun regCodeTest() {
        setupTest("handlers.regCode")

        val devid = RandomID.fromString(ADMIN_PROFILE_DATA["devid"])!!
        val devkey = CryptoString.fromString(ADMIN_PROFILE_DATA["device.public"]!!)

        // Test Case #1: Regcode a user
        val db = DBConn()
        val regInfo = preregUser(db, "csimons")
        CommandTest(
            "regcode.1",
            SessionState(
                ClientRequest(
                    "REGCODE", mutableMapOf(
                        "Reg-Code" to regInfo["Reg-Code"]!!,
                        "User-ID" to "csimons",
                        "Password-Hash" to "this is a pretty terrible password",
                        "Password-Salt" to "somekindofsalt",
                        "Password-Algorithm" to "cleartext",
                        "Device-ID" to devid.toString(),
                        "Device-Key" to devkey.toString(),
                        "Device-Info" to "XSALSA20:SomethingIDontCare"
                    )
                ), null, LoginState.NoSession
            ), ::commandRegCode
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            response.assertReturnCode(201)
            assertEquals("csimons", response.data["User-ID"])
            assertEquals(gServerDomain.toString(), response.data["Domain"])
            assert(response.data.containsKey("Workspace-ID"))
            assertNotNull(RandomID.fromString(response.data["Workspace-ID"]))

            val rs = db.query(
                "SELECT * FROM workspaces WHERE wid=?",
                response.data["Workspace-ID"]!!
            ).getOrThrow()
            assert(rs.next())
            assertEquals("csimons", rs.getString("uid"))
            assertEquals("example.com", rs.getString("domain"))
            assertEquals("individual", rs.getString("wtype"))
            assertEquals("active", rs.getString("status"))
            assertEquals("cleartext", rs.getString("passtype"))
            assertEquals("somekindofsalt", rs.getString("salt"))
            assert(rs.getString("passparams").isNullOrEmpty())
        }.run()
    }

    @Test
    fun registerTest() {
        setupTest("handlers.register")
        val config = ServerConfig.load().getOrThrow()
        config.setValue("global.registration", "network")?.let { throw it }

        // Test Case #1: Supply no data. Expect WID and Domain
        CommandTest(
            "register.1",
            SessionState(
                ClientRequest(
                    "REGISTER", mutableMapOf(
                        "Password-Hash" to "This is a pretty terrible password",
                        "Password-Algorithm" to "cleartext",
                        "Device-ID" to "adcf13a6-fe21-4a8e-9ebf-2546ec9657b9",
                        "Device-Key" to "CURVE25519:MyFakeDeviceKeyLOL",
                        "Device-Info" to "CURVE25519:MyDeviceInfoIsFake2"
                    )
                ), null, LoginState.NoSession
            ),
            ::commandRegister
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            assertEquals(201, response.code)
            assertEquals(gServerDomain.toString(), response.data["Domain"])
            assertNotNull(RandomID.fromString(response.data["Workspace-ID"]))
        }.run()

        // Test Case #2: Supply wid and user ID
        val regUser = RandomID.fromString("994c3383-2cde-4fc2-a486-a0e5e7a034dc")
        CommandTest(
            "register.2",
            SessionState(
                ClientRequest(
                    "REGISTER", mutableMapOf(
                        "Workspace-ID" to regUser.toString(),
                        "User-ID" to "csimons",
                        "Password-Hash" to "This is a pretty terrible password",
                        "Password-Algorithm" to "cleartext",
                        "Device-ID" to "adcf13a6-fe21-4a8e-9ebf-2546ec9657b9",
                        "Device-Key" to "CURVE25519:MyFakeDeviceKeyLOL",
                        "Device-Info" to "CURVE25519:MyDeviceInfoIsFake2"
                    )
                ), null, LoginState.NoSession
            ),
            ::commandRegister
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            assertEquals(201, response.code)
            assertEquals(gServerDomain.toString(), response.data["Domain"])
            assertEquals(regUser.toString(), response.data["Workspace-ID"])

            val db = DBConn()
            val rs = db.query("SELECT uid FROM workspaces WHERE wid=?", regUser.toString())
                .getOrThrow()
            assert(rs.next())
            assertEquals("csimons", rs.getString("uid"))
        }.run()

        // TODO: Implement test for REGISTER
    }
}