package mensagod.handlers

import keznacl.CryptoString
import keznacl.EncryptionPair
import libkeycard.RandomID
import libkeycard.UserID
import libmensago.ClientRequest
import libmensago.ServerResponse
import mensagod.*
import mensagod.dbcmds.WorkspaceStatus
import mensagod.dbcmds.WorkspaceType
import mensagod.dbcmds.addDevice
import mensagod.dbcmds.addWorkspace
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import testsupport.*
import java.net.InetAddress
import java.net.Socket

class RegCmdTest {
    @Test
    fun archiveTest() {
        setupTest("handlers.archive")
        val db = DBConn()
        setupUser(db)
        setupKeycard(db, true, USER_PROFILE_DATA)

        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        val userWID = RandomID.fromString(USER_PROFILE_DATA["wid"])!!

        // Test Case #1: Try to archive admin
        CommandTest(
            "archive.1",
            SessionState(
                ClientRequest(
                    "ARCHIVE", mutableMapOf(
                        "Password-Hash" to ADMIN_PROFILE_DATA["passhash"]!!,
                    )
                ), adminWID,
                LoginState.LoggedIn
            ), ::commandArchive
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(401)
        }.run()

        // Create a quickie user account for the next few test cases
        val user2WID = RandomID.fromString("fe46d15f-eb31-43f2-8fee-fd9088e8fba3")!!
        val user2UID = UserID.fromString("rbrannan")
        val dev2id = RandomID.fromString("ac669438-0954-4dd7-b698-a71e33b06eee")!!
        val dev2key = EncryptionPair.generate().getOrThrow().pubKey
        val fakeInfo = CryptoString.fromString("XSALSA20:abcdefg1234567890")!!
        addWorkspace(
            db, user2WID, user2UID, gServerDomain, USER_PROFILE_DATA["passhash"]!!,
            "argon2id", "ejzAtaom5H1y6wnLHvrb7g", "m=65536,t=2,p=1",
            WorkspaceStatus.Active, WorkspaceType.Individual
        )?.let { throw it }
        addDevice(db, userWID, dev2id, dev2key, fakeInfo, DeviceStatus.Registered)?.let { throw it }

        // Test Case #2: User tries to archive someone else
        CommandTest(
            "archive.2",
            SessionState(
                ClientRequest(
                    "ARCHIVE", mutableMapOf(
                        "Password-Hash" to USER_PROFILE_DATA["password"]!!,
                        "Workspace-ID" to user2WID.toString(),
                    )
                ), userWID,
                LoginState.LoggedIn
            ), ::commandArchive
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(403)
        }.run()

        // Test Case #3: User successfully archives themselves
        CommandTest(
            "archive.3",
            SessionState(
                ClientRequest(
                    "ARCHIVE", mutableMapOf(
                        "Password-Hash" to USER_PROFILE_DATA["password"]!!,
                    )
                ), userWID,
                LoginState.LoggedIn
            ), ::commandArchive
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(202)
        }.run()

        // Test Case #4: Admin archives another workspace
        CommandTest(
            "archive.4",
            SessionState(
                ClientRequest(
                    "ARCHIVE", mutableMapOf(
                        "Password-Hash" to ADMIN_PROFILE_DATA["passhash"]!!,
                        "Workspace-ID" to USER_PROFILE_DATA["wid"]!!,
                    )
                ), adminWID,
                LoginState.LoggedIn
            ), ::commandArchive
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(401)
        }.run()
    }

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

        // Test Case #1: Try to register on a server with private registration
        config.setValue("global.registration", "private")?.let { throw it }
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
            assertEquals(304, response.code)
        }.run()

        config.setValue("global.registration", "network")?.let { throw it }

        // Test Case #2: Supply no data. Expect WID and Domain
        CommandTest(
            "register.2",
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

        // Test Case #3: Supply wid and user ID
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

        // Test Case #4: Try to register with missing required information
        listOf("Password-Hash", "Password-Algorithm", "Device-ID", "Device-Key", "Device-Info")
            .forEach {
                val data = mutableMapOf(
                    "Password-Hash" to "This is a pretty terrible password",
                    "Password-Algorithm" to "cleartext",
                    "Device-ID" to "adcf13a6-fe21-4a8e-9ebf-2546ec9657b9",
                    "Device-Key" to "CURVE25519:MyFakeDeviceKeyLOL",
                    "Device-Info" to "CURVE25519:MyDeviceInfoIsFake2"
                )
                data.remove(it)

                CommandTest(
                    "register.4",
                    SessionState(
                        ClientRequest("REGISTER", data), null, LoginState.NoSession
                    ),
                    ::commandRegister
                ) { port ->
                    val socket = Socket(InetAddress.getByName("localhost"), port)
                    val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

                    if (response.code != 400) {
                        throw TestFailureException("Failed to catch missing required field $it")
                    }
                }.run()
            }
    }
}