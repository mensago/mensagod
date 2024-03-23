package mensagod.dbcmds

import keznacl.SigningPair
import libkeycard.MAddress
import libkeycard.OrgEntry
import libkeycard.RandomID
import libkeycard.UserEntry
import mensagod.DBConn
import mensagod.ServerConfig
import mensagod.resetDB
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import testsupport.ADMIN_PROFILE_DATA
import testsupport.initDB
import testsupport.setupTest

class DBKeycardCmdTest {

    @Test
    fun addEntryTest() {
        setupTest("dbcmds.addEntries")
        val db = DBConn()
        val osPair = getPrimarySigningPair(db).getOrThrow()
        val orgEntry = OrgEntry.fromString(getRawEntries(db, null, 0U).getOrThrow()[0])
            .getOrThrow()
        val crsPair = SigningPair.fromStrings(
            ADMIN_PROFILE_DATA["signing.public"]!!,
            ADMIN_PROFILE_DATA["signing.private"]!!
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
            sign("Organization-Signature", osPair)?.let { throw it }
            addAuthString("Previous-Hash", orgEntry.getAuthString("Hash")!!)
                ?.let { throw it }
            hash()?.let { throw it }
            sign("User-Signature", crsPair)?.let { throw it }
        }
        addEntry(db, rootEntry)?.let { throw it }

        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        val userEntries = getRawEntries(db, adminWID).getOrThrow()
        assertEquals(1, userEntries.size)
        db.disconnect()
    }

    @Test
    fun getEntriesTest() {
        setupTest("dbcmds.getEntries")
        val db = DBConn()

        val currentEntryList = getRawEntries(db, null, 0U).getOrThrow()
        assertEquals(1, currentEntryList.size)
        val current = OrgEntry.fromString(currentEntryList[0]).getOrThrow()
        assertEquals(2, current.getFieldInteger("Index")!!)

        val rootEntryList = getRawEntries(db, null, 1U, 1U).getOrThrow()
        assertEquals(1, rootEntryList.size)
        val root = OrgEntry.fromString(rootEntryList[0]).getOrThrow()
        assertEquals(1, root.getFieldInteger("Index")!!)

        val allEntriesList = getRawEntries(db, null).getOrThrow()
        assertEquals(2, allEntriesList.size)
        val first = OrgEntry.fromString(allEntriesList[0]).getOrThrow()
        assertEquals(1, first.getFieldInteger("Index")!!)
        val second = OrgEntry.fromString(allEntriesList[1]).getOrThrow()
        assertEquals(2, second.getFieldInteger("Index")!!)

        val secondEntryList = getRawEntries(db, null, 2U).getOrThrow()
        assertEquals(1, secondEntryList.size)
        val secondOnly = OrgEntry.fromString(secondEntryList[0]).getOrThrow()
        assertEquals(2, secondOnly.getFieldInteger("Index")!!)
        db.disconnect()
    }

    @Test
    fun resolveWIDAddressTest() {
        val config = ServerConfig.load().getOrThrow()
        resetDB(config).getOrThrow()
        DBConn.initialize(config)?.let { throw it }
        val db = DBConn().connect().getOrThrow()
        initDB(db.getConnection()!!)

        // Using support instead of admin because we don't have to go through the registration
        // process for admin this way.
        assertNotNull(
            resolveAddress(db, MAddress.fromString("support/example.com")!!)
                .getOrThrow()
        )

        // admin hasn't been registered yet, so this one should be null
        assertNull(
            resolveAddress(db, MAddress.fromString("admin/example.com")!!)
                .getOrThrow()
        )

        val zeroWID = RandomID.fromString("00000000-0000-0000-0000-000000000000")!!
        assertNull(resolveWID(db, zeroWID).getOrThrow())
        db.disconnect()
    }
}