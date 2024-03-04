package mensagod.handlers

import keznacl.EncryptionPair
import libkeycard.RandomID
import libkeycard.WAddress
import libmensago.*
import libmensago.resolver.KCResolver
import mensagod.*
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import testsupport.*
import java.net.InetAddress
import java.net.Socket

class MiscCmdTest {

    @Test
    fun getWIDTest() {
        val config = ServerConfig.load().getOrThrow()
        resetDB(config).getOrThrow()
        DBConn.initialize(config)?.let { throw it }
        val serverData = initDB(DBConn().connect().getOrThrow().getConnection()!!)

        val state = SessionState(
            message = ClientRequest("GETWID", mutableMapOf("User-ID" to "support"))
        )

        CommandTest("getWID", state, ::commandGetWID) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            assertEquals(200, response.code)
            assertEquals(serverData["support_wid"]!!, response.data["Workspace-ID"])
        }.run()
    }

    @Test
    fun sendTest() {
        setupTest("handlers.send")
        KCResolver.dns = FakeDNSHandler()

        val db = DBConn()
        setupKeycard(db, false, ADMIN_PROFILE_DATA)
        setupUser(db)
        setupKeycard(db, false, USER_PROFILE_DATA)

        val adminAddr = WAddress.fromString(ADMIN_PROFILE_DATA["waddress"])!!
        val userAddr = WAddress.fromString(USER_PROFILE_DATA["waddress"])!!
        val userPair = EncryptionPair.fromStrings(
            USER_PROFILE_DATA["encryption.public"]!!,
            USER_PROFILE_DATA["encryption.private"]!!
        ).getOrThrow()

        val msg1 = Message(adminAddr, userAddr, MsgFormat.Text)
            .setSubject("Test Subject")
            .setBody("This is a test message")
        val sealed1 = Envelope.seal(userPair, msg1).getOrThrow()
        val sealed1Str = sealed1.toStringResult().getOrThrow()

        // Test Case #1: Success
        CommandTest(
            "send.1",
            SessionState(
                ClientRequest(
                    "SEND", mutableMapOf(
                        "Message" to sealed1Str,
                        "Domain" to userAddr.domain.toString(),
                    )
                ), adminAddr.id,
                LoginState.LoggedIn, RandomID.fromString(ADMIN_PROFILE_DATA["devid"])!!
            ), ::commandSend
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            response.assertReturnCode(200)
        }.run()


        // TODO: Implement test for commandSend()
    }
}
