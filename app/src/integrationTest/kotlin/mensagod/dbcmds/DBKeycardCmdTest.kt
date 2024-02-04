package mensagod.dbcmds

import libkeycard.MAddress
import libkeycard.OrgEntry
import libkeycard.RandomID
import libkeycard.UserEntry
import mensagod.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class DBKeycardCmdTest {

    @Test fun addEntriesTest() {
        setupTest("dbcmds.addEntries")
        val db = DBConn()
        val osPair = getPrimarySigningPair(db)

        val rootEntry = UserEntry()
        rootEntry.run {
            setFieldInteger("Index", 1)
            setField("Name", ADMIN_PROFILE_DATA["name"]!!)
            setField("Workspace-ID", ADMIN_PROFILE_DATA["wid"]!!)
            setField("User-ID", ADMIN_PROFILE_DATA["uid"]!!)
            setField("Domain", ADMIN_PROFILE_DATA["domain"]!!)
            setField("Contact-Request-Verification-Key",
                ADMIN_PROFILE_DATA["crsigning.public"]!!)
            setField("Contact-Request-Encryption-Key",
                ADMIN_PROFILE_DATA["crencryption.public"]!!)
            setField("Verification-Key", ADMIN_PROFILE_DATA["signing.public"]!!)
            setField("Encryption-Key", ADMIN_PROFILE_DATA["encryption.public"]!!)
            sign("Organization-Signature", osPair)?.let { throw it }
        }
//        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!

        // TODO: Implement addEntries test
    }

    @Test fun getEntriesTest() {
        setupTest("dbcmds.getEntries")
        val db = DBConn()

        val currentEntryList = getEntries(db, null, 0U)
        assertEquals(1, currentEntryList.size)
        val current = OrgEntry.fromString(currentEntryList[0]).getOrThrow()
        assertEquals(2, current.getFieldInteger("Index")!!)

        val rootEntryList = getEntries(db, null, 1U, 1U)
        assertEquals(1, rootEntryList.size)
        val root = OrgEntry.fromString(rootEntryList[0]).getOrThrow()
        assertEquals(1, root.getFieldInteger("Index")!!)

        val allEntriesList = getEntries(db, null)
        assertEquals(2, allEntriesList.size)
        val first = OrgEntry.fromString(allEntriesList[0]).getOrThrow()
        assertEquals(1, first.getFieldInteger("Index")!!)
        val second = OrgEntry.fromString(allEntriesList[1]).getOrThrow()
        assertEquals(2, second.getFieldInteger("Index")!!)

        val secondEntryList = getEntries(db, null, 2U)
        assertEquals(1, secondEntryList.size)
        val secondOnly = OrgEntry.fromString(secondEntryList[0]).getOrThrow()
        assertEquals(2, secondOnly.getFieldInteger("Index")!!)
    }

    @Test
    fun resolveWIDAddressTest() {
        val config = ServerConfig.load()
        resetDB(config)
        DBConn.initialize(config)
        val db = DBConn().connect()
        val setupData = initDB(db.getConnection()!!)

        // Using support instead of admin because we don't have to go through the registration
        // process for admin this way.
        assertNotNull(resolveAddress(db, MAddress.fromString("support/example.com")!!))

        // admin hasn't been registered yet, so this one should be null
        assertNull(resolveAddress(db, MAddress.fromString("admin/example.com")!!))

        val supportWID = RandomID.fromString(setupData["support_wid"])!!
        assertEquals("example.com", resolveWID(db, supportWID)?.domain.toString())
        assertNull(resolveWID(db,
            RandomID.fromString("00000000-0000-0000-0000-000000000000")!!))
    }
}