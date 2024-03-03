package mensagod.handlers

import keznacl.CryptoString
import keznacl.SigningPair
import libkeycard.Keycard
import libkeycard.OrgEntry
import libkeycard.RandomID
import libkeycard.UserEntry
import libmensago.ClientRequest
import libmensago.ServerResponse
import mensagod.DBConn
import mensagod.LoginState
import mensagod.SessionState
import mensagod.dbcmds.getEntries
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import testsupport.*
import java.net.InetAddress
import java.net.Socket

class KeycardCmdTest {

    // With all of the possible error states in commandAddEntry(), this test class could be
    // absolutely gargantuan. We're just going to test the most common states for now.

    @Test
    fun commandAddEntryTest() {
        setupTest("handlers.addEntry")

        val db = DBConn()
        val orgEntry = OrgEntry.fromString(getEntries(db, null, 0U).getOrThrow()[0])
            .getOrThrow()
        val crsPair = SigningPair.fromStrings(
            ADMIN_PROFILE_DATA["crsigning.public"]!!,
            ADMIN_PROFILE_DATA["crsigning.private"]!!
        ).getOrThrow()

        val rootEntry = UserEntry()
        rootEntry.run {
            setFieldInteger("Index", 1)
            setField("Name", ADMIN_PROFILE_DATA["name"]!!)
            setField("Workspace-ID", ADMIN_PROFILE_DATA["wid"]!!)
            setField("User-ID", ADMIN_PROFILE_DATA["uid"]!!)
            setField("Domain", ADMIN_PROFILE_DATA["domain"]!!)
            setField(
                "Contact-Request-Verification-Key",
                ADMIN_PROFILE_DATA["crsigning.public"]!!
            )
            setField(
                "Contact-Request-Encryption-Key",
                ADMIN_PROFILE_DATA["crencryption.public"]!!
            )
            setField("Verification-Key", ADMIN_PROFILE_DATA["signing.public"]!!)
            setField("Encryption-Key", ADMIN_PROFILE_DATA["encryption.public"]!!)
        }

        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!

        // Test Case #1: Successfully add root user entry
        CommandTest(
            "addEntry.1",
            SessionState(
                ClientRequest(
                    "ADDENTRY", mutableMapOf(
                        "Base-Entry" to rootEntry.getFullText("Organization-Signature").getOrThrow()
                    )
                ), adminWID, LoginState.LoggedIn
            ), ::commandAddEntry
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            var response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            response.assertReturnCode(100)
            assert(response.data.containsKey("Organization-Signature"))
            rootEntry.run {
                addAuthString(
                    "Organization-Signature",
                    CryptoString.fromString(response.data["Organization-Signature"]!!)!!
                )
                    ?.let { throw it }
                addAuthString("Previous-Hash", orgEntry.getAuthString("Hash")!!)
                    ?.let { throw it }
                hash()?.let { throw it }
                sign("User-Signature", crsPair)?.let { throw it }
            }

            ClientRequest(
                "ADDENTRY", mutableMapOf(
                    "Base-Entry" to rootEntry.getFullText(null).getOrThrow(),
                    "Previous-Hash" to rootEntry.getAuthString("Previous-Hash")!!.toString(),
                    "Hash" to rootEntry.getAuthString("Hash")!!.toString(),
                    "User-Signature" to rootEntry.getAuthString("User-Signature")!!.toString()
                )
            ).send(socket.getOutputStream())

            response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(200)
        }.run()

        val keycard = Keycard.new("User")!!
        keycard.entries.add(rootEntry)
        val newkeys = keycard.chain(crsPair).getOrThrow()
        val newEntry = keycard.current!!
        val newCRSPair = SigningPair.from(
            newkeys["crsigning.public"]!!,
            newkeys["crsigning.private"]!!
        ).getOrThrow()

        // Test Case #2: Successfully add second user entry
        CommandTest(
            "addEntry.2",
            SessionState(
                ClientRequest(
                    "ADDENTRY", mutableMapOf(
                        "Base-Entry" to newEntry.getFullText("Organization-Signature").getOrThrow(),
                    )
                ), adminWID, LoginState.LoggedIn
            ), ::commandAddEntry
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            var response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            response.assertReturnCode(100)
            assert(response.data.containsKey("Organization-Signature"))
            newEntry.run {
                addAuthString(
                    "Organization-Signature",
                    CryptoString.fromString(response.data["Organization-Signature"]!!)!!
                )
                    ?.let { throw it }
                addAuthString(
                    "Previous-Hash",
                    newEntry.getAuthString("Previous-Hash")!!
                )?.let { throw it }
                hash()?.let { throw it }
                sign("User-Signature", newCRSPair)?.let { throw it }
            }

            ClientRequest(
                "ADDENTRY", mutableMapOf(
                    "Base-Entry" to newEntry.getFullText(null).getOrThrow(),
                    "Previous-Hash" to rootEntry.getAuthString("Hash")!!.toString(),
                    "Hash" to newEntry.getAuthString("Hash")!!.toString(),
                    "User-Signature" to newEntry.getAuthString("User-Signature")!!.toString()
                )
            ).send(socket.getOutputStream())

            response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(200)
        }.run()
    }

    @Test
    fun commandGetOrgCardTest() {
        setupTest("handlers.getOrgCard")

        // Test Case #1: Successfully get organization card
        CommandTest(
            "getOrgCard.1",
            SessionState(
                ClientRequest("GETCARD", mutableMapOf("Start-Index" to "1")), null,
                LoginState.NoSession
            ), ::commandGetCard
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            var response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            response.assertReturnCode(104)
            assert(response.checkFields(listOf(Pair("Item-Count", true), Pair("Total-Size", true))))
            assertEquals("2", response.data["Item-Count"])

            val db = DBConn()
            val entries = getEntries(db, null, 1U).getOrThrow()
            assertEquals(2, entries.size)
            val expectedSize = entries[0].length + entries[1].length + 96
            assertEquals(expectedSize, response.data["Total-Size"]!!.toInt())

            ClientRequest("TRANSFER", mutableMapOf()).send(socket.getOutputStream())
            response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(200)
            assert(response.data.containsKey("Card-Data"))
            assertEquals(expectedSize, response.data["Card-Data"]!!.length)
        }.run()

        // Test Case #2: Get organization's current entry only
        CommandTest(
            "getOrgCard.2",
            SessionState(
                ClientRequest("GETCARD", mutableMapOf("Start-Index" to "0")), null,
                LoginState.NoSession
            ), ::commandGetCard
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            var response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            response.assertReturnCode(104)
            assert(response.checkFields(listOf(Pair("Item-Count", true), Pair("Total-Size", true))))
            assertEquals("1", response.data["Item-Count"])

            val db = DBConn()
            val entries = getEntries(db, null, 0U).getOrThrow()
            assertEquals(1, entries.size)
            val expectedSize = entries[0].length + 48
            assertEquals(expectedSize, response.data["Total-Size"]!!.toInt())

            ClientRequest("TRANSFER", mutableMapOf()).send(socket.getOutputStream())
            response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(200)
            assert(response.data.containsKey("Card-Data"))
            assertEquals(expectedSize, response.data["Card-Data"]!!.length)

            val card = Keycard.fromString(response.data["Card-Data"]!!).getOrThrow()
            assertEquals(1, card.entries.size)
            assertEquals("Organization", card.entryType)
            assertEquals(2, card.current!!.getFieldInteger("Index"))
        }.run()

        // Test Case #3: Get organization's first entry only
        CommandTest(
            "getOrgCard.3",
            SessionState(
                ClientRequest(
                    "GETCARD", mutableMapOf(
                        "Start-Index" to "1",
                        "End-Index" to "1",
                    )
                ), null, LoginState.NoSession
            ), ::commandGetCard
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            var response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            response.assertReturnCode(104)
            assert(response.checkFields(listOf(Pair("Item-Count", true), Pair("Total-Size", true))))
            assertEquals("1", response.data["Item-Count"])

            val db = DBConn()
            val entries = getEntries(db, null, 1U, 1U).getOrThrow()
            assertEquals(1, entries.size)
            val expectedSize = entries[0].length + 48
            assertEquals(expectedSize, response.data["Total-Size"]!!.toInt())

            ClientRequest("TRANSFER", mutableMapOf()).send(socket.getOutputStream())
            response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(200)
            assert(response.data.containsKey("Card-Data"))
            assertEquals(expectedSize, response.data["Card-Data"]!!.length)

            val card = Keycard.fromString(response.data["Card-Data"]!!).getOrThrow()
            assertEquals(1, card.entries.size)
            assertEquals("Organization", card.entryType)
            assertEquals(1, card.current!!.getFieldInteger("Index"))
        }.run()
    }

    @Test
    fun commandIsCurrentTest() {
        setupTest("handlers.getUserCard")

        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!

        // Test Case #1: Org card check isn't current
        CommandTest(
            "isCurrent.1",
            SessionState(
                ClientRequest(
                    "ISCURRENT", mutableMapOf(
                        "Index" to "1",
                    )
                ), null,
                LoginState.NoSession
            ), ::commandIsCurrent
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(200)
            response.assertField("Is-Current") { it == "NO" }
        }.run()

        // Test Case #2: Org card check is current
        CommandTest(
            "isCurrent.2",
            SessionState(
                ClientRequest(
                    "ISCURRENT", mutableMapOf(
                        "Index" to "2",
                    )
                ), null,
                LoginState.NoSession
            ), ::commandIsCurrent
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(200)
            response.assertField("Is-Current") { it == "YES" }
        }.run()

        // Test Case #3: User card check -- doesn't exist
        CommandTest(
            "isCurrent.3",
            SessionState(
                ClientRequest(
                    "ISCURRENT", mutableMapOf(
                        "Workspace-ID" to adminWID.toString(),
                        "Index" to "2",
                    )
                ), null,
                LoginState.NoSession
            ), ::commandIsCurrent
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(404)
        }.run()
    }

    @Test
    fun commandGetUserCardTest() {
        setupTest("handlers.getUserCard")

        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!

        // Test Case #1: Request nonexistent keycard
        CommandTest(
            "getUserCard.1",
            SessionState(
                ClientRequest(
                    "GETCARD", mutableMapOf(
                        "Owner" to adminWID.toString(),
                        "Start-Index" to "1",
                    )
                ), null,
                LoginState.NoSession
            ), ::commandGetCard
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(404)
        }.run()

        val db = DBConn()
        setupAdminKeycard(db, true)

        // Test Case #2: Request entire keycard
        CommandTest(
            "getUserCard.2",
            SessionState(
                ClientRequest(
                    "GETCARD", mutableMapOf(
                        "Owner" to adminWID.toString(),
                        "Start-Index" to "1",
                    )
                ), null,
                LoginState.NoSession
            ), ::commandGetCard
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            var response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            response.assertReturnCode(104)
            assert(response.checkFields(listOf(Pair("Item-Count", true), Pair("Total-Size", true))))
            assertEquals("2", response.data["Item-Count"])

            val entries = getEntries(db, adminWID, 1U).getOrThrow()
            assertEquals(2, entries.size)
            val expectedSize = entries[0].length + 48 + entries[1].length + 48
            assertEquals(expectedSize, response.data["Total-Size"]!!.toInt())

            ClientRequest("TRANSFER", mutableMapOf()).send(socket.getOutputStream())
            response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(200)
            assert(response.data.containsKey("Card-Data"))
            assertEquals(expectedSize, response.data["Card-Data"]!!.length)
        }.run()
    }
}