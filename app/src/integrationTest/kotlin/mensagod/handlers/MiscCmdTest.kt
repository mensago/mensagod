package mensagod.handlers

import keznacl.CryptoString
import keznacl.EncryptionPair
import libkeycard.RandomID
import libkeycard.WAddress
import libmensago.*
import libmensago.resolver.KCResolver
import mensagod.*
import mensagod.dbcmds.*
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
        setupTest("handlers.getwid")

        // Test Case #1: Success
        CommandTest(
            "getWID", SessionState(
                ClientRequest("GETWID").attach("User-ID", "admin")
            ), ::commandGetWID
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(200)
            assertEquals(ADMIN_PROFILE_DATA["wid"], response.data["Workspace-ID"])
        }.run()

        // Test Case #1: Not found
        CommandTest(
            "getWID", SessionState(
                ClientRequest("GETWID").attach("User-ID", "unknownUser")
            ), ::commandGetWID
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            ServerResponse.receive(socket.getInputStream()).getOrThrow().assertReturnCode(404)
        }.run()
    }

    @Test
    fun idleTest() {
        setupTest("handlers.idle")
        ServerConfig.load().getOrThrow()
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!

        // Test Case #1: No Updates Requested
        CommandTest(
            "idle.1",
            SessionState(
                ClientRequest("IDLE"), null, LoginState.NoSession
            ), ::commandIdle
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            ServerResponse.receive(socket.getInputStream()).getOrThrow().assertReturnCode(200)
        }.run()

        val clientPath = CryptoString.fromString("XSALSA20:abcdefg")!!
        val devid = RandomID.fromString(ADMIN_PROFILE_DATA["devid"])!!
        val db = DBConn()

        addSyncRecord(
            db, adminWID, SyncRecord(
                RandomID.generate(),
                UpdateType.Mkdir,
                "/ wsp $adminWID ad139db2-253e-49be-8981-5937ea9dfce0:$clientPath",
                "1700000000",
                devid
            )
        )
        addSyncRecord(
            db, adminWID, SyncRecord(
                RandomID.generate(),
                UpdateType.Mkdir,
                "/ wsp $adminWID ad139db2-253e-49be-8981-5937ea9dfce0 " +
                        "db4edc98-6eb3-4695-a48c-c7158050307e:$clientPath",
                "1700001000",
                devid
            )
        )
        addSyncRecord(
            db, adminWID, SyncRecord(
                RandomID.generate(),
                UpdateType.Mkdir,
                "/ wsp $adminWID ff2b1e04-78af-42f8-8029-da3c2751aa84:$clientPath",
                "1700002000",
                devid
            )
        )

        // Test Case #2: Success / Some Updates
        CommandTest(
            "idle.2",
            SessionState(
                ClientRequest("IDLE", mutableMapOf("CountUpdates" to "1700000050")), adminWID,
                LoginState.LoggedIn, RandomID.fromString(ADMIN_PROFILE_DATA["devid"])!!
            ), ::commandIdle
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            response.assertReturnCode(200)
            assert(response.data.containsKey("UpdateCount"))
            assertEquals("2", response.data["UpdateCount"])
        }.run()

        // Test Case #3: Failure / no login
        CommandTest(
            "idle.3",
            SessionState(
                ClientRequest("IDLE", mutableMapOf("CountUpdates" to "1700000050")), null,
                LoginState.NoSession
            ), ::commandIdle
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            ServerResponse.receive(socket.getInputStream()).getOrThrow().assertReturnCode(401)
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

    @Test
    fun sendLargeTest() {
        // TODO: Implement test for SENDLARGE
    }

    @Test
    fun setStatusTest() {
        setupTest("handlers.setStatus")
        val db = DBConn()
        setupUser(db)

        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        val userWID = RandomID.fromString(USER_PROFILE_DATA["wid"])!!

        // Test Case #1: User tries to use the command
        CommandTest(
            "setStatus.1",
            SessionState(
                ClientRequest(
                    "SETSTATUS", mutableMapOf(
                        "Workspace-ID" to adminWID.toString(),
                        "Status" to WorkspaceStatus.Suspended.toString(),
                    )
                ), userWID,
                LoginState.LoggedIn
            ), ::commandSetStatus
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            response.assertReturnCode(403)
        }.run()

        // Test Case #2: Admin uses an invalid status
        CommandTest(
            "setStatus.2",
            SessionState(
                ClientRequest(
                    "SETSTATUS", mutableMapOf(
                        "Workspace-ID" to userWID.toString(),
                        "Status" to "confusion",
                    )
                ), adminWID,
                LoginState.LoggedIn
            ), ::commandSetStatus
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            response.assertReturnCode(400)
        }.run()

        // Test Case #3: Success
        var rs = db.query("SELECT status FROM workspaces WHERE wid=?", userWID).getOrThrow()
        assert(rs.next())
        assertEquals(WorkspaceStatus.Active.toString(), rs.getString("status"))
        CommandTest(
            "setStatus.3",
            SessionState(
                ClientRequest(
                    "SETSTATUS", mutableMapOf(
                        "Workspace-ID" to userWID.toString(),
                        "Status" to WorkspaceStatus.Disabled.toString(),
                    )
                ), adminWID,
                LoginState.LoggedIn
            ), ::commandSetStatus
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            response.assertReturnCode(200)
            rs = db.query("SELECT status FROM workspaces WHERE wid=?", userWID).getOrThrow()
            assert(rs.next())
            assertEquals(WorkspaceStatus.Disabled.toString(), rs.getString("status"))

        }.run()
    }
}
