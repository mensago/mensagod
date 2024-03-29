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
import testsupport.ADMIN_PROFILE_DATA
import testsupport.setupTest

class DBLoginCmdTest {

    @Test
    fun checkPasswordTest() {
        setupTest("dbcmds.checkPassword")
        val db = DBConn()
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        assert(checkPassword(db, adminWID, ADMIN_PROFILE_DATA["password"]!!).getOrThrow())
        assertFalse(checkPassword(db, adminWID, "foobar").getOrThrow())
        val badWID = RandomID.fromString("be8e1ae7-1915-4d82-bb21-fa5565788cef")!!
        val error = checkPassword(db, badWID, "foobar")
        assert(error.isFailure)
        assert(error.exceptionOrNull() is ResourceNotFoundException)
        db.disconnect()
    }

    @Test
    fun preregWorkspaceTest() {
        // This test also covers deletePrereg() and checkRegCode()

        setupTest("dbcmds.checkPassword")
        val db = DBConn()

        val testHash = ADMIN_PROFILE_DATA["reghash"]!!
        val testCode = ADMIN_PROFILE_DATA["regcode"]!!
        val newWID = RandomID.fromString("94fd481f-6b1c-459b-ada7-5f32b3a1bbf3")!!
        val newWID2 = RandomID.fromString("793e9e33-5c6b-4b6a-8f56-ef64e7db2c21")!!
        val newUID = UserID.fromString("csimons")!!
        val domain = gServerDomain

        preregWorkspace(db, newWID, newUID, domain, testHash)?.let { throw it }
        var rs = db.query("SELECT wid,uid,domain,regcode FROM prereg WHERE wid=?", newWID)
            .getOrThrow()
        assert(rs.next())
        assertEquals(newWID.toString(), rs.getString("wid"))
        assertEquals(newUID.toString(), rs.getString("uid"))
        assertEquals(domain.toString(), rs.getString("domain"))
        assertEquals(testHash, rs.getString("regcode"))

        assert(preregWorkspace(db, newWID, newUID, domain, testHash) is ResourceExistsException)

        deletePrereg(db, WAddress.fromParts(newWID, domain))?.let { throw it }
        preregWorkspace(db, newWID, newUID, domain, testHash)?.let { throw it }

        preregWorkspace(db, newWID2, null, domain, testHash)?.let { throw it }
        rs = db.query("SELECT wid,uid,domain,regcode FROM prereg WHERE wid=?", newWID2)
            .getOrThrow()
        assert(rs.next())
        assertEquals(newWID2.toString(), rs.getString("wid"))
        assertNull(rs.getString("uid"))
        assertEquals(domain.toString(), rs.getString("domain"))

        var regInfo = checkRegCode(db, MAddress.fromParts(newUID, domain), testCode).getOrThrow()!!
        assertEquals(newWID, regInfo.first)
        assertEquals(newUID, regInfo.second)

        regInfo = checkRegCode(db, MAddress.fromParts(UserID.fromWID(newWID), domain), testCode)
            .getOrThrow()!!
        assertEquals(newWID, regInfo.first)
        assertEquals(newUID, regInfo.second)

        assertNull(checkRegCode(db, MAddress.fromParts(newUID, domain), "baz").getOrThrow())
        db.disconnect()
    }
}
