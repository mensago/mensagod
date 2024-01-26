package mensagod.dbcmds

import libkeycard.MAddress
import libkeycard.RandomID
import libkeycard.UserID
import libkeycard.WAddress
import mensagod.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class DBLoginCmdTest {

    @Test
    fun checkPasswordTest() {
        setupTest("dbcmds.checkPassword")
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        assert(checkPassword(DBConn(), adminWID, ADMIN_PROFILE_DATA["password"]!!))
        assertFalse(checkPassword(DBConn(), adminWID, "foobar"))
        assertThrows<ResourceNotFoundException> {
            val badWID = RandomID.fromString("be8e1ae7-1915-4d82-bb21-fa5565788cef")!!
            checkPassword(DBConn(), badWID, "foobar")
        }
    }

    @Test
    fun preregWorkspaceTest() {
        // This test also covers deletePrereg() and checkRegCode()

        val config = ServerConfig.load()
        resetDB(config)
        DBConn.initialize(config)
        val db = DBConn().connect()
        val serverData = initDB(db.getConnection()!!)

        val newWID = RandomID.fromString("94fd481f-6b1c-459b-ada7-5f32b3a1bbf3")!!
        val newWID2 = RandomID.fromString("793e9e33-5c6b-4b6a-8f56-ef64e7db2c21")!!
        val newUID = UserID.fromString("csimons")!!
        val supportWID = RandomID.fromString(serverData["support_wid"])!!
        val supportUID = UserID.fromString("support")
        val domain = gServerDomain
        assertThrows<ResourceExistsException> {
            preregWorkspace(db, supportWID, null, domain, "foo")
        }
        assertThrows<ResourceExistsException> {
            preregWorkspace(db, supportWID, supportUID, domain, "bar")
        }

        preregWorkspace(db, newWID, newUID, domain, "baz")
        var rs = db.query("SELECT wid,uid,domain,regcode FROM prereg WHERE wid=?", newWID)
        assert(rs.next())
        assertEquals(newWID.toString(), rs.getString("wid"))
        assertEquals(newUID.toString(), rs.getString("uid"))
        assertEquals(domain.toString(), rs.getString("domain"))
        assertEquals("baz", rs.getString("regcode"))

        assertThrows<ResourceExistsException> {
            preregWorkspace(db, newWID, newUID, domain, "spam")
        }

        deletePrereg(db, WAddress.fromParts(newWID, domain))
        preregWorkspace(db, newWID, newUID, domain, "baz")

        preregWorkspace(db, newWID2, null, domain, "eggs")
        rs = db.query("SELECT wid,uid,domain,regcode FROM prereg WHERE wid=?", newWID2)
        assert(rs.next())
        assertEquals(newWID2.toString(), rs.getString("wid"))
        assertNull(rs.getString("uid"))
        assertEquals(domain.toString(), rs.getString("domain"))
        assertEquals("eggs", rs.getString("regcode"))

        var regInfo = checkRegCode(db, MAddress.fromParts(newUID, domain), "baz")!!
        assertEquals(newWID, regInfo.first)
        assertEquals(newUID, regInfo.second)

        regInfo = checkRegCode(db, MAddress.fromParts(UserID.fromWID(newWID), domain), "baz")!!
        assertEquals(newWID, regInfo.first)
        assertEquals(newUID, regInfo.second)

        assertNull(checkRegCode(db, MAddress.fromParts(newUID, domain), "foo"))
    }
}
