package mensagod.dbcmds

import libkeycard.MAddress
import libkeycard.RandomID
import libkeycard.UserID
import libkeycard.WAddress
import libmensago.ResourceExistsException
import libmensago.ResourceNotFoundException
import mensagod.DBConn
import mensagod.gServerDomain
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import testsupport.ADMIN_PROFILE_DATA
import testsupport.setupTest

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

        val setupData = setupTest("dbcmds.checkPassword")
        val db = DBConn()

        val testHash = ADMIN_PROFILE_DATA["reghash"]!!
        val testCode = ADMIN_PROFILE_DATA["regcode"]!!
        val newWID = RandomID.fromString("94fd481f-6b1c-459b-ada7-5f32b3a1bbf3")!!
        val newWID2 = RandomID.fromString("793e9e33-5c6b-4b6a-8f56-ef64e7db2c21")!!
        val newUID = UserID.fromString("csimons")!!
        val supportWID = RandomID.fromString(setupData.serverSetupData["support_wid"])!!
        val supportUID = UserID.fromString("support")
        val domain = gServerDomain
        assertThrows<ResourceExistsException> {
            preregWorkspace(db, supportWID, null, domain, "foo")
        }
        assertThrows<ResourceExistsException> {
            preregWorkspace(db, supportWID, supportUID, domain, "bar")
        }

        preregWorkspace(db, newWID, newUID, domain, testHash)
        var rs = db.query("SELECT wid,uid,domain,regcode FROM prereg WHERE wid=?", newWID)
            .getOrThrow()
        assert(rs.next())
        assertEquals(newWID.toString(), rs.getString("wid"))
        assertEquals(newUID.toString(), rs.getString("uid"))
        assertEquals(domain.toString(), rs.getString("domain"))
        assertEquals(testHash, rs.getString("regcode"))

        assertThrows<ResourceExistsException> {
            preregWorkspace(db, newWID, newUID, domain, testHash)
        }

        deletePrereg(db, WAddress.fromParts(newWID, domain))
        preregWorkspace(db, newWID, newUID, domain, testHash)

        preregWorkspace(db, newWID2, null, domain, testHash)
        rs = db.query("SELECT wid,uid,domain,regcode FROM prereg WHERE wid=?", newWID2)
            .getOrThrow()
        assert(rs.next())
        assertEquals(newWID2.toString(), rs.getString("wid"))
        assertNull(rs.getString("uid"))
        assertEquals(domain.toString(), rs.getString("domain"))

        var regInfo = checkRegCode(db, MAddress.fromParts(newUID, domain), testCode)!!
        assertEquals(newWID, regInfo.first)
        assertEquals(newUID, regInfo.second)

        regInfo = checkRegCode(db, MAddress.fromParts(UserID.fromWID(newWID), domain), testCode)!!
        assertEquals(newWID, regInfo.first)
        assertEquals(newUID, regInfo.second)

        assertNull(checkRegCode(db, MAddress.fromParts(newUID, domain), "baz"))
    }
}
