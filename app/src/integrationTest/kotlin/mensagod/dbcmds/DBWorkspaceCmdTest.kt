package mensagod.dbcmds

import libkeycard.RandomID
import libkeycard.UserID
import mensagod.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class DBWorkspaceCmdTest {

    @Test
    fun addWorkspaceSetStatusTest() {
        val config = ServerConfig.load().getOrThrow()
        resetDB(config).getOrThrow()
        DBConn.initialize(config)
        val db = DBConn().connect()
        initDB(db.getConnection()!!)

        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        val adminUID = UserID.fromString("admin")!!
        addWorkspace(db, adminWID, adminUID, gServerDomain, "somepasshash",
            "passalgorithm", "salt", "passparams", WorkspaceStatus.Active,
            WorkspaceType.Individual)

        val rs = db.query("""SELECT * FROM workspaces WHERE wid=?""", adminWID)
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
        assertEquals(WorkspaceStatus.Archived, checkWorkspace(db, adminWID))
        assertThrows<ResourceExistsException> {
            addWorkspace(db, adminWID, adminUID, gServerDomain, "somepasshash",
                "passalgorithm", "salt", "passparams", WorkspaceStatus.Active,
                WorkspaceType.Individual)
        }
    }

    @Test
    fun checkWorkspaceUserIDTest() {
        val config = ServerConfig.load().getOrThrow()
        resetDB(config).getOrThrow()
        DBConn.initialize(config)
        val db = DBConn().connect()
        val serverData = initDB(db.getConnection()!!)

        assertEquals(
            WorkspaceStatus.Active,
            checkWorkspace(db, RandomID.fromString(serverData["support_wid"])!!)
        )
        assertNull(
            checkWorkspace(db,
                RandomID.fromString("00000000-0000-0000-0000-000000000000")!!
            )
        )

        assertNotNull(resolveUserID(db, UserID.fromString("support")!!))
        assertNull(resolveUserID(db,
                UserID.fromString("00000000-0000-0000-0000-000000000000")!!
        ))
    }
}
