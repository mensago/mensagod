package mensagod.handlers

import keznacl.CryptoString
import libkeycard.RandomID
import libmensago.ClientRequest
import libmensago.ServerResponse
import mensagod.DBConn
import mensagod.LoginState
import mensagod.ServerConfig
import mensagod.SessionState
import mensagod.dbcmds.SyncRecord
import mensagod.dbcmds.UpdateType
import mensagod.dbcmds.addSyncRecord
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import testsupport.ADMIN_PROFILE_DATA
import testsupport.assertReturnCode
import testsupport.setupTest
import java.net.InetAddress
import java.net.Socket

class SyncCmdTest {

    @Test
    fun getUpdatesTest() {
        setupTest("handlers.getUpdates")
        ServerConfig.load().getOrThrow()
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!

        // Test Case #1: Success / No Updates
        CommandTest(
            "getUpdates.1",
            SessionState(
                ClientRequest("GETUPDATES", mutableMapOf("Time" to "0")), adminWID,
                LoginState.LoggedIn, RandomID.fromString(ADMIN_PROFILE_DATA["devid"])!!
            ), ::commandGetUpdates
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            response.assertReturnCode(200)
            assert(response.data.containsKey("UpdateCount"))
            assertEquals("0", response.data["UpdateCount"])
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
            "getUpdates.2",
            SessionState(
                ClientRequest("GETUPDATES", mutableMapOf("Time" to "1700000050")), adminWID,
                LoginState.LoggedIn, RandomID.fromString(ADMIN_PROFILE_DATA["devid"])!!
            ), ::commandGetUpdates
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            response.assertReturnCode(200)
            assert(response.data.containsKey("UpdateCount"))
            assertEquals("2", response.data["UpdateCount"])
            listOf("Update0", "Update1").forEach { assert(response.data.containsKey(it)) }
        }.run()

        // Test Case #3: Failure: Missing Field
        CommandTest(
            "getUpdates.3",
            SessionState(
                ClientRequest("GETUPDATES", mutableMapOf()), adminWID, LoginState.LoggedIn,
                RandomID.fromString(ADMIN_PROFILE_DATA["devid"])!!
            ), ::commandGetUpdates
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            response.assertReturnCode(400)
        }.run()
        db.disconnect()
    }
}
