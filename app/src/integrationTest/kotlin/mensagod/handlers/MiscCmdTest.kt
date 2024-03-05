package mensagod.handlers

import keznacl.EncryptionPair
import libkeycard.RandomID
import libkeycard.WAddress
import libmensago.*
import libmensago.resolver.KCResolver
import mensagod.*
import mensagod.dbcmds.getSyncRecords
import mensagod.delivery.resetDelivery
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import testsupport.*
import java.lang.Thread.sleep
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
            // This sleep call is needed to ensure the delivery thread has enough time to process
            // the sent message and add the sync record to the database.
            sleep(100)

            response.assertReturnCode(200)

            // While the return code says that the item was successfully queued for delivery, the
            // rest of this proves that it was successfully delivered and able to be read by the
            // user. In short, this code proves that local delivery _completely_ works.
            val syncList = getSyncRecords(db, userAddr.id, 0).getOrThrow()
            assertEquals(1, syncList.size)
            val item = syncList[0]
            assertEquals(item.devid, gServerDevID)

            val lfs = LocalFS.get()
            val itemHandle = lfs.entry(MServerPath(item.data))
            assert(itemHandle.exists().getOrThrow())
            val received = Envelope.loadFile(itemHandle.getFile()).getOrThrow()
            val openedMsg = received.open(userPair).getOrThrow()
            assertEquals(msg1.subject, openedMsg.subject)
            assertEquals(msg1.body, openedMsg.body)
        }.run()
        resetDelivery()

        // Test Case #2: Try to send a message that's too big
        val tooBigSealed = Envelope.seal(
            userPair, Message(adminAddr, userAddr, MsgFormat.Text)
                .setSubject("This Message Is Too Big for SEND()")
                .setBody("\uD83D\uDE08".repeat(6_500_000))
        ).getOrThrow()
        println("tooBig size: ${tooBigSealed.message.toString().length}")

        CommandTest(
            "send.2",
            SessionState(
                ClientRequest(
                    "SEND", mutableMapOf(
                        "Message" to tooBigSealed.toString(),
                        "Domain" to userAddr.domain.toString(),
                    )
                ), adminAddr.id,
                LoginState.LoggedIn, RandomID.fromString(ADMIN_PROFILE_DATA["devid"])!!
            ), ::commandSend
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            sleep(100)

            response.assertReturnCode(414)
        }.run()
    }
}
