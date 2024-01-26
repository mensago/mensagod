package mensagod.commands

import keznacl.EncryptionKey
import keznacl.EncryptionPair
import libkeycard.RandomID
import mensagod.*
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.net.InetAddress
import java.net.Socket

class LoginCmdTest {

    @Test
    fun loginTest() {
        val setupData = setupTest("commands.loginTest")
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        val serverKey = EncryptionKey.fromString(setupData.serverSetupData["oekey"]!!).getOrThrow()

        // We use a predetermined challenge here to make debugging easier
        val challenge = "iZghMZcgOOa|x+ZRj3QOr&0C%UuOyl@EgSR4}fFL"
        val encrypted = serverKey.encrypt(challenge.encodeToByteArray()).getOrThrow()

        // Test Case #1: Successfully log in in as admin
        CommandTest("login.1",
            SessionState(ClientRequest("LOGIN", mutableMapOf(
                "Login-Type" to "PLAIN",
                "Workspace-ID" to adminWID.toString(),
                "Challenge" to encrypted.toString(),
            )), null,
                LoginState.NoSession), ::commandLogin) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            assertReturnCode(100, response)
            assert(response.checkFields(listOf(
                Pair("Response", true),
                Pair("Password-Algorithm", true),
                Pair("Password-Salt", true),
                Pair("Password-Parameters", true),
            )))
            assertEquals(challenge, response.data["Response"])
            assertEquals("argon2id", response.data["Password-Algorithm"])
            assertEquals("anXvadxtNJAYa2cUQFqKSQ", response.data["Password-Salt"])
            assertEquals("m=65536,t=2,p=1", response.data["Password-Parameters"])
        }.run()

        // Test Case #2: Login-Type missing
        CommandTest("login.2",
            SessionState(ClientRequest("LOGIN", mutableMapOf(
                // Leave out Login-Type
                "Workspace-ID" to adminWID.toString(),
                "Challenge" to encrypted.toString(),
            )), null,
                LoginState.NoSession), ::commandLogin) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            assertReturnCode(400, response)
        }.run()

        // Test Case #3: Decryption failure
        val badChallenge = EncryptionPair.generate().getOrThrow()
            .encrypt(challenge.encodeToByteArray()).getOrThrow()

        CommandTest("login.3",
            SessionState(ClientRequest("LOGIN", mutableMapOf(
                "Login-Type" to "PLAIN",
                "Workspace-ID" to adminWID.toString(),
                "Challenge" to badChallenge.toString(),
            )), null,
                LoginState.NoSession), ::commandLogin) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            assertReturnCode(306, response)
        }.run()

        // Test Case #4: Bad login state
        CommandTest("login.4",
            SessionState(ClientRequest("LOGIN", mutableMapOf(
                "Login-Type" to "PLAIN",
                "Workspace-ID" to adminWID.toString(),
                "Challenge" to challenge,
            )), null,
                LoginState.LoggedIn), ::commandLogin) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            assertReturnCode(400, response)
        }.run()
    }

    @Test
    fun logoutTest() {
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        CommandTest("logout.1",
            SessionState(ClientRequest("LOGOUT"), adminWID,
                LoginState.LoggedIn), ::commandLogout) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            assertReturnCode(200, response)
        }.run()

    }

    @Test
    fun passwordTest() {
        setupTest("commands.passwordTest")
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!

        // Test Case #1: Successful password auth as admin
        CommandTest("password.1",
            SessionState(ClientRequest("PASSWORD", mutableMapOf(
                "Password-Hash" to ADMIN_PROFILE_DATA["password"]!!,
            )), adminWID,
                LoginState.AwaitingPassword), ::commandPassword) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            assertReturnCode(100, response)
            assert(response.data.isEmpty())
        }.run()

        // Test Case #2: Password auth failure as admin
        CommandTest("password.2",
            SessionState(ClientRequest("PASSWORD", mutableMapOf(
                "Password-Hash" to "foobar",
            )), adminWID,
                LoginState.AwaitingPassword), ::commandPassword) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            assertReturnCode(402, response)
            assert(response.data.isEmpty())
        }.run()
    }
}
