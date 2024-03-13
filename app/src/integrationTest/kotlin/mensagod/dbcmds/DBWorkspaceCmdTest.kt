package mensagod.dbcmds

import libkeycard.RandomID
import libkeycard.UserID
import libmensago.ResourceExistsException
import mensagod.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import testsupport.ADMIN_PROFILE_DATA
import testsupport.initDB
import testsupport.setupTest

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
        addWorkspace(
            db, adminWID, adminUID, gServerDomain, "somepasshash",
            "passalgorithm", "salt", "passparams", WorkspaceStatus.Active,
            WorkspaceType.Individual
        )?.let { throw it }

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

        setWorkspaceStatus(db, adminWID, WorkspaceStatus.Archived)?.let { throw it }
        assertEquals(WorkspaceStatus.Archived, checkWorkspace(db, adminWID).getOrThrow())
        assertThrows<ResourceExistsException> {
            addWorkspace(
                db, adminWID, adminUID, gServerDomain, "somepasshash",
                "passalgorithm", "salt", "passparams", WorkspaceStatus.Active,
                WorkspaceType.Individual
            )?.let { throw it }
        }
    }

    @Test
    fun archiveWorkspaceTest() {
        val setupData = setupTest("dbcmds.isAlias")
        val db = DBConn()

        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        assert(archiveWorkspace(db, adminWID) is UnauthorizedException)
        // TODO: Finish implementing archiveWorkspaceTest
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
            checkWorkspace(
                db,
                RandomID.fromString("00000000-0000-0000-0000-000000000000")!!
            ).getOrThrow()
        )

        assertNotNull(resolveUserID(db, UserID.fromString("support")!!).getOrThrow())
        val zeroUID = UserID.fromString("00000000-0000-0000-0000-000000000000")!!
        assertNull(resolveUserID(db, zeroUID).getOrThrow())
    }

    @Test
    fun isAliasTest() {
        setupTest("dbcmds.isAlias")
        val db = DBConn()
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        assertNull(
            resolveAlias(db, UserID.fromString("admin")!!, gServerDomain)
                .getOrThrow()
        )
        assertEquals(
            adminWID, resolveAlias(db, UserID.fromString("support")!!, gServerDomain)
                .getOrThrow()
        )
        assertEquals(
            adminWID,
            resolveAlias(db, UserID.fromString("abuse")!!, gServerDomain).getOrThrow()
        )
    }

    @Test
    fun makeGetAliasTest() {
        setupTest("dbcmds.isAlias")
        val db = DBConn()

        val adminUID = UserID.fromString("admin")!!
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        assert(
            makeAlias(
                db,
                adminWID,
                adminUID,
                gServerDomain
            ) is ResourceExistsException
        )

        makeAlias(db, adminWID, UserID.fromString("admin2")!!, gServerDomain)?.let { throw it }
        makeAlias(db, adminWID, UserID.fromString("admin3")!!, gServerDomain)?.let { throw it }
        val aliases = getAliases(db, adminWID).getOrThrow()
        assertEquals(4, aliases.size)
    }
}
