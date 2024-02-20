package mensagod.dbcmds

import libkeycard.RandomID
import libkeycard.UserID
import libmensago.ResourceExistsException
import mensagod.DBConn
import mensagod.ServerConfig
import mensagod.gServerDomain
import mensagod.resetDB
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import testsupport.ADMIN_PROFILE_DATA
import testsupport.initDB

class DBWorkspaceCmdTest {

    @Test
    fun addWorkspaceSetStatusTest() {
        val config = ServerConfig.load().getOrThrow()
        resetDB(config).getOrThrow()
        DBConn.initialize(config)?.let { throw it }
        val db = DBConn().connect().getOrThrow()
        initDB(db.getConnection()!!)

        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        val adminUID = UserID.fromString("admin")!!
        addWorkspace(db, adminWID, adminUID, gServerDomain, "somepasshash",
            "passalgorithm", "salt", "passparams", WorkspaceStatus.Active,
            WorkspaceType.Individual)?.let { throw it }

        val rs = db.query("""SELECT * FROM workspaces WHERE wid=?""", adminWID).getOrThrow()
        assert(rs.next())
        assertEquals("admin", rs.getString("uid"))
        assertEquals(gServerDomain.toString(), rs.getString("domain"))
        assertEquals("somepasshash", rs.getString("password"))
        assertEquals("passalgorithm", rs.getString("passtype"))
        assertEquals("salt", rs.getString("salt"))
        assertEquals("passparams", rs.getString("passparams"))
        assertEquals("active", rs.getString("status"))
        assertEquals("individual", rs.getString("wtype"))

        setWorkspaceStatus(db, adminWID, WorkspaceStatus.Archived)
        assertEquals(WorkspaceStatus.Archived, checkWorkspace(db, adminWID).getOrThrow())
        assertThrows<ResourceExistsException> {
            addWorkspace(db, adminWID, adminUID, gServerDomain, "somepasshash",
                "passalgorithm", "salt", "passparams", WorkspaceStatus.Active,
                WorkspaceType.Individual)?.let { throw it }
        }
    }

    @Test
    fun checkWorkspaceUserIDTest() {
        val config = ServerConfig.load().getOrThrow()
        resetDB(config).getOrThrow()
        DBConn.initialize(config)?.let { throw it }
        val db = DBConn().connect().getOrThrow()
        val serverData = initDB(db.getConnection()!!)

        assertEquals(
            WorkspaceStatus.Active,
            checkWorkspace(db, RandomID.fromString(serverData["support_wid"])!!).getOrThrow()
        )
        assertNull(
            checkWorkspace(db,
                RandomID.fromString("00000000-0000-0000-0000-000000000000")!!
            ).getOrThrow()
        )

        assertNotNull(resolveUserID(db, UserID.fromString("support")!!).getOrThrow())
        val zeroUID = UserID.fromString("00000000-0000-0000-0000-000000000000")!!
        assertNull(resolveUserID(db, zeroUID).getOrThrow())
    }
}
