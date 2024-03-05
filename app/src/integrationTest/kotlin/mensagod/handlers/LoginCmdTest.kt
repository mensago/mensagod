package mensagod.handlers

import keznacl.CryptoString
import keznacl.EncryptionKey
import keznacl.EncryptionPair
import libkeycard.RandomID
import libkeycard.Timestamp
import libmensago.ClientRequest
import libmensago.Envelope
import libmensago.MServerPath
import libmensago.ServerResponse
import mensagod.*
import mensagod.dbcmds.getSyncRecords
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import testsupport.ADMIN_PROFILE_DATA
import testsupport.assertReturnCode
import testsupport.setupKeycard
import testsupport.setupTest
import java.net.InetAddress
import java.net.Socket

class LoginCmdTest {

    @Test
    fun deviceTest() {
        setupTest("handlers.deviceTest")
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!

        // Actually create some fake device info for the test
        val devInfo = mapOf(
            "Name" to "dellxps",
            "User" to "CSimons",
            "OS" to "Ubuntu 22.04",
            "Device-ID" to ADMIN_PROFILE_DATA["devid"]!!,
            "Device-Key" to ADMIN_PROFILE_DATA["device.public"]!!,
            "Timestamp" to Timestamp().toString(),
        )
        val userKey = EncryptionKey.fromString(ADMIN_PROFILE_DATA["encryption.public"]!!)
            .getOrThrow()
        val encInfo = userKey.encrypt(devInfo.toString().encodeToByteArray()).getOrThrow()

        // Test Case #1: Successfully complete first device auth phase
        CommandTest(
            "device.1",
            SessionState(
                ClientRequest(
                    "DEVICE", mutableMapOf(
                        "Device-ID" to ADMIN_PROFILE_DATA["devid"]!!,
                        "Device-Key" to ADMIN_PROFILE_DATA["device.public"]!!,
                        "Device-Info" to encInfo.toString(),
                    )
                ), adminWID,
                LoginState.AwaitingDeviceID
            ), ::commandDevice
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            var response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(100)
            response.checkFields(listOf(Pair("Challenge", true)))

            // The challenge from the server is expected to be Base85-encoded random bytes that are
            // encrypted into a CryptoString. This means we decrypt the challenge and send the resulting
            // decrypted string back to the server as proof of device identity.

            val devPair = EncryptionPair.fromStrings(
                ADMIN_PROFILE_DATA["device.public"]!!,
                ADMIN_PROFILE_DATA["device.private"]!!
            ).getOrThrow()
            val challStr = CryptoString.fromString(response.data["Challenge"]!!)!!
            val challDecrypted = devPair.decrypt(challStr).getOrThrow().decodeToString()

            val req = ClientRequest(
                "DEVICE", mutableMapOf(
                    "Device-ID" to ADMIN_PROFILE_DATA["devid"]!!,
                    "Device-Key" to ADMIN_PROFILE_DATA["device.public"]!!,
                    "Device-Info" to encInfo.toString(),
                    "Response" to challDecrypted,
                )
            )
            req.send(socket.getOutputStream())
            response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(200)

        }.run()
        val db = DBConn()
        setupKeycard(db, false, ADMIN_PROFILE_DATA)

        // Test Case #2: Successfully complete second device auth phase
        val adminPair = EncryptionPair.fromStrings(
            ADMIN_PROFILE_DATA["encryption.public"]!!,
            ADMIN_PROFILE_DATA["encryption.private"]!!
        ).getOrThrow()
        val devid2 = RandomID.fromString("35ee6e0d-add8-49ea-a70a-edd0b53db3e8")!!
        val dev2pair = EncryptionPair.generate().getOrThrow()
        val devInfo2 = mapOf(
            "Name" to "myframework",
            "User" to "Corbin",
            "OS" to "Windows 10 Pro",
            "Device-ID" to devid2.toString(),
            "Device-Key" to dev2pair.publicKey.toString(),
            "Timestamp" to Timestamp().toString(),
        )
        val encInfo2 = userKey.encrypt(devInfo2.toString().encodeToByteArray()).getOrThrow()
        CommandTest(
            "device.2",
            SessionState(
                ClientRequest(
                    "DEVICE", mutableMapOf(
                        "Device-ID" to devid2.toString(),
                        "Device-Key" to dev2pair.publicKey.toString(),
                        "Device-Info" to encInfo2.toString(),
                    )
                ), adminWID,
                LoginState.AwaitingDeviceID
            ), ::commandDevice
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            Thread.sleep(100)

            response.assertReturnCode(105)

            val syncList = getSyncRecords(db, adminWID, 0).getOrThrow()
            assertEquals(1, syncList.size)
            val item = syncList[0]
            assertEquals(item.devid, gServerDevID)

            val lfs = LocalFS.get()
            val itemHandle = lfs.entry(MServerPath(item.data))
            assert(itemHandle.exists().getOrThrow())
            val received = Envelope.loadFile(itemHandle.getFile()).getOrThrow()
            val devRequest = received.open(adminPair).getOrThrow()
            println(devRequest)

            // TODO: Add multidevice test case to DEVICE
        }.run()

    }

    @Test
    fun loginTest() {
        val setupData = setupTest("handlers.loginTest")
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        val serverKey = EncryptionKey.fromString(setupData.serverSetupData["oekey"]!!).getOrThrow()

        // We use a predetermined challenge here to make debugging easier
        val challenge = "iZghMZcgOOa|x+ZRj3QOr&0C%UuOyl@EgSR4}fFL"
        val encrypted = serverKey.encrypt(challenge.encodeToByteArray()).getOrThrow()

        // Test Case #1: Successfully log in in as admin
        var session = SessionState(
            ClientRequest(
                "LOGIN", mutableMapOf(
                    "Login-Type" to "PLAIN",
                    "Workspace-ID" to adminWID.toString(),
                    "Challenge" to encrypted.toString(),
                )
            ), null,
            LoginState.NoSession
        )
        CommandTest("login.1", session, ::commandLogin) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            response.assertReturnCode(100)
            assert(
                response.checkFields(
                    listOf(
                        Pair("Response", true),
                        Pair("Password-Algorithm", true),
                        Pair("Password-Salt", true),
                        Pair("Password-Parameters", true),
                    )
                )
            )
            assertEquals(challenge, response.data["Response"])
            assertEquals("argon2id", response.data["Password-Algorithm"])
            assertEquals("anXvadxtNJAYa2cUQFqKSQ", response.data["Password-Salt"])
            assertEquals("m=65536,t=2,p=1", response.data["Password-Parameters"])
        }.run()

        // Test Case #2: Login-Type missing
        CommandTest(
            "login.2",
            SessionState(
                ClientRequest(
                    "LOGIN", mutableMapOf(
                        // Leave out Login-Type
                        "Workspace-ID" to adminWID.toString(),
                        "Challenge" to encrypted.toString(),
                    )
                ), null,
                LoginState.NoSession
            ), ::commandLogin
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            response.assertReturnCode(400)
        }.run()

        // Test Case #3: Decryption failure
        val badChallenge = EncryptionPair.generate().getOrThrow()
            .encrypt(challenge.encodeToByteArray()).getOrThrow()

        CommandTest(
            "login.3",
            SessionState(
                ClientRequest(
                    "LOGIN", mutableMapOf(
                        "Login-Type" to "PLAIN",
                        "Workspace-ID" to adminWID.toString(),
                        "Challenge" to badChallenge.toString(),
                    )
                ), null,
                LoginState.NoSession
            ), ::commandLogin
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            response.assertReturnCode(306)
        }.run()

        // Test Case #4: Bad login state
        CommandTest(
            "login.4",
            SessionState(
                ClientRequest(
                    "LOGIN", mutableMapOf(
                        "Login-Type" to "PLAIN",
                        "Workspace-ID" to adminWID.toString(),
                        "Challenge" to challenge,
                    )
                ), null,
                LoginState.LoggedIn
            ), ::commandLogin
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            response.assertReturnCode(400)
        }.run()
    }

    @Test
    fun logoutTest() {
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        CommandTest(
            "logout.1",
            SessionState(
                ClientRequest("LOGOUT"), adminWID,
                LoginState.LoggedIn
            ), ::commandLogout
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            response.assertReturnCode(200)
        }.run()

    }

    @Test
    fun passwordTest() {
        setupTest("handlers.passwordTest")
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!

        // Test Case #1: Successful password auth as admin
        CommandTest(
            "password.1",
            SessionState(
                ClientRequest(
                    "PASSWORD", mutableMapOf(
                        "Password-Hash" to ADMIN_PROFILE_DATA["password"]!!,
                    )
                ), adminWID,
                LoginState.AwaitingPassword
            ), ::commandPassword
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            response.assertReturnCode(100)
            assert(response.data.isEmpty())
        }.run()

        // Test Case #2: Password auth failure as admin
        CommandTest(
            "password.2",
            SessionState(
                ClientRequest(
                    "PASSWORD", mutableMapOf(
                        "Password-Hash" to "foobar",
                    )
                ), adminWID,
                LoginState.AwaitingPassword
            ), ::commandPassword
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            response.assertReturnCode(402)
            assert(response.data.isEmpty())
        }.run()
    }
}
