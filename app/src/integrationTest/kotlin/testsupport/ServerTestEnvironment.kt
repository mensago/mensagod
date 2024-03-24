package testsupport

import keznacl.CryptoString
import keznacl.EncryptionPair
import keznacl.SigningPair
import libkeycard.*
import libmensago.MServerPath
import libmensago.resolver.KCResolver
import mensagod.*
import mensagod.dbcmds.*
import mensagod.handlers.DeviceStatus
import org.apache.commons.io.FileUtils
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.nio.file.Paths

/*
    Tests are written such that they (a) don't care about how they connect to the database, so
    long as they can and (b) don't care where in the filesystem their files are stored so long
    as they have a place to work in standard setup, so why not abstract away the details.

    Some tests will need mock server-side data and some will not. This needs to support both.
 */

const val SETUP_TEST_FILESYSTEM: Int = 1
const val SETUP_TEST_DATABASE: Int = 2
const val SETUP_TEST_ADMIN: Int = 3
const val SETUP_TEST_USER: Int = 4
const val SETUP_TEST_ADMIN_KEYCARD: Int = 6
const val SETUP_TEST_BOTH_KEYCARDS: Int = 7

/**
 * This support class is responsible for setting up the server side of anenvironment for integration
 * tests.
 *
 * NOTE: If a test requires database setup, the user account utilized to connect to the database
 * must have CREATEDB privileges to create a database for each test. This is to permit
 * parallelization and prevent test from stepping on one another's toes.
 */
class ServerTestEnvironment(val testName: String) {
    private val dbconfig: PGConfig = PGConfig(dbname = testName)
    private var db: PGConn? = null
    private var serverPrimary: SigningPair? = null
    private var serverEncryption: EncryptionPair? = null
    private var serverCard: Keycard? = null

    val serverconfig: ServerConfig = ServerConfig.load().getOrThrow()
    val testPath: String = Paths.get("build", "testfiles", testName).toAbsolutePath()
        .toString()

    /**
     * Provisions the test environment based on the configuration set
     */
    fun provision(provisionLevel: Int): ServerTestEnvironment {
        setupTestBase()
        if (provisionLevel >= SETUP_TEST_DATABASE)
            initDatabase()
        if (provisionLevel >= SETUP_TEST_ADMIN)
            regAdmin()
        if (provisionLevel >= SETUP_TEST_USER)
            regUser()
        if (provisionLevel >= SETUP_TEST_ADMIN_KEYCARD)
            setupKeycard(gAdminProfileData)
        if (provisionLevel >= SETUP_TEST_BOTH_KEYCARDS)
            setupKeycard(gUserProfileData)

        return this
    }

    /**
     * Shuts down the test environment. This is primarily to close any database connections.
     */
    fun done() {
        db?.disconnect()
    }

    /**
     * Returns a connection to the database. This will throw an exception if the database connection
     * has not been initialized.
     */
    fun getDB(): PGConn {
        return db ?: throw TestFailureException("Database not initialized")
    }

    /**
     * Returns the server's current primary signing keypair or throws an exception. This call
     * requires database initialization.
     */
    fun serverPrimaryPair(): SigningPair {
        return serverPrimary ?: throw TestFailureException("Database not initialized")
    }

    /**
     * Returns the server's current encryption keypair or throws an exception. This call requires
     * database initialization.
     */
    fun serverEncryptionPair(): EncryptionPair {
        return serverEncryption ?: throw TestFailureException("Database not initialized")
    }

    /**
     * Provisions the integration test folder hierarchy and environment baseline. The test root
     * contains one subfolder, topdir, which is the server's workspace data folder. This also
     * provides other filesystem-related setup, such as initializing logging, LocalFS, and the
     * mock DNS handler.
     */
    private fun setupTestBase() {
        val topdir = Paths.get(testPath, "topdir")
        val topdirFile = topdir.toFile()
        if (topdirFile.exists())
            FileUtils.cleanDirectory(topdirFile)
        else
            topdirFile.mkdirs()

        listOf("wsp", "out", "tmp", "keys").forEach {
            Paths.get(topdir.toString(), it).toFile().mkdir()
        }

        initLogging(Paths.get(testPath, "log.txt"), true)
        LocalFS.initialize(topdir.toString())?.let { throw it }
        KCResolver.dns = FakeDNSHandler()
        gServerDomain = Domain.fromString(serverconfig.getString("global.domain"))!!
        gServerAddress = WAddress.fromParts(gServerDevID, gServerDomain)
    }

    /**
     * Ensures that the database to be used by the test exists
     */
    private fun ensureDB() {
        serverconfig.setValue("database.name", testName)
        val dbsetupcfg = PGConfig(
            serverconfig.getString("database.user")!!,
            serverconfig.getString("database.password")!!,
            serverconfig.getString("database.host")!!,
            serverconfig.getInteger("database.port")!!,
            "postgres"
        )
        // Swallow the exception if we fail to create the database. It simplifies the logic a lot
        // as Postgres doesn't have a CREATE IF NOT EXISTS syntax for database creation. If we fail
        // to create the database for other reasons, the test will fail later on.
        kotlin.runCatching {
            PGConn(dbsetupcfg).execute("CREATE DATABASE $testName OWNER ${dbsetupcfg.user}")
        }
    }

    /**
     * Provisions a database for the integration test. The database is populated with all tables
     * needed and adds basic data to the database as if setup had been run. It also rotates the org
     * keycard so that there are two entries.
     */
    private fun initDatabase() {
        ensureDB()
        resetDB(serverconfig).getOrThrow().close()
        db = PGConn(dbconfig)
        DBConn.initialize(serverconfig)?.let { throw it }

        val initialOSPair = SigningPair.fromStrings(
            "ED25519:r#r*RiXIN-0n)BzP3bv`LA&t4LFEQNF0Q@\$N~RF*",
            "ED25519:{UNQmjYhz<(-ikOBYoEQpXPt<irxUF*nq25PoW=_"
        ).getOrThrow()
        val initialOEPair = EncryptionPair.fromStrings(
            "CURVE25519:SNhj2K`hgBd8>G>lW\$!pXiM7S-B!Fbd9jT2&{{Az",
            "CURVE25519:WSHgOhi+bg=<bO^4UoJGF-z9`+TBN{ds?7RZ;w3o"
        ).getOrThrow()

        val rootEntry = OrgEntry().run {
            setFieldInteger("Index", 1)
            setField("Name", "Example, Inc.")
            setField(
                "Contact-Admin",
                "ae406c5e-2673-4d3e-af20-91325d9623ca/example.com"
            )
            setField("Language", "en")
            setField("Domain", "example.com")
            setField("Primary-Verification-Key", initialOSPair.pubKey.toString())
            setField("Encryption-Key", initialOEPair.pubKey.toString())

            isDataCompliant()?.let { throw it }
            hash()?.let { throw it }
            sign("Organization-Signature", initialOSPair)?.let { throw it }
            verifySignature("Organization-Signature", initialOSPair).getOrThrow()
            isCompliant()?.let { throw it }
            this
        }

        serverCard = Keycard.new("Organization")!!
        serverCard!!.entries.add(rootEntry)

        db!!.execute(
            "INSERT INTO keycards(owner,creationtime,index,entry,fingerprint) " +
                    "VALUES('organization',?,?,?,?);",
            rootEntry.getFieldString("Timestamp")!!,
            rootEntry.getFieldInteger("Index")!!,
            rootEntry.getFullText(null).getOrThrow(),
            rootEntry.getAuthString("Hash")!!
        )

        val keys = serverCard!!.chain(initialOSPair, 365).getOrThrow()
        val newEntry = serverCard!!.entries[1]

        db!!.execute(
            "INSERT INTO keycards(owner,creationtime,index,entry,fingerprint) " +
                    "VALUES('organization',?,?,?,?);",
            newEntry.getFieldString("Timestamp")!!,
            newEntry.getFieldInteger("Index")!!,
            newEntry.getFullText(null).getOrThrow(),
            newEntry.getAuthString("Hash")!!
        )

        db!!.execute(
            "INSERT INTO orgkeys(creationtime,pubkey,privkey,purpose,fingerprint) " +
                    "VALUES(?,?,?,'encrypt',?);",
            newEntry.getFieldString("Timestamp")!!,
            keys["encryption.public"]!!,
            keys["encryption.private"]!!,
            keys["encryption.public"]!!.hash().getOrThrow()
        )

        db!!.execute(
            "INSERT INTO orgkeys(creationtime,pubkey,privkey,purpose,fingerprint) " +
                    "VALUES(?,?,?,'sign',?);",
            newEntry.getFieldString("Timestamp")!!,
            keys["primary.public"]!!,
            keys["primary.private"]!!,
            keys["primary.public"]!!.hash().getOrThrow()
        )

        // Preregister the admin account
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"]!!)!!
        db!!.execute(
            "INSERT INTO prereg(wid,uid,domain,regcode) VALUES(?,?,?,?)",
            adminWID, "admin", "example.com", ADMIN_PROFILE_DATA["reghash"]!!
        )

        // Forward abuse and support to admin
        db!!.execute(
            "INSERT INTO workspaces(wid,uid,domain,password,passtype,status,wtype) " +
                    "VALUES(?,'abuse','example.com','-','','active','alias')",
            adminWID
        )
        db!!.execute(
            "INSERT INTO workspaces(wid,uid,domain,password,passtype,status,wtype) " +
                    "VALUES(?,'support','example.com','-','','active','alias')",
            adminWID
        )
    }

    /**
     * Registers the admin user and the admin's first device
     */
    private fun regAdmin() {
        val fakeInfo = CryptoString.fromString("XSALSA20:ABCDEFG1234567890")!!
        val db = DBConn()
        addWorkspace(
            db, gAdminProfileData.wid, gAdminProfileData.uid, gServerDomain,
            gAdminProfileData.passhash,
            "argon2id", "anXvadxtNJAYa2cUQFqKSQ", "m=65536,t=2,p=1",
            WorkspaceStatus.Active, WorkspaceType.Individual
        )?.let { throw it }
        addDevice(
            db,
            gAdminProfileData.wid,
            gAdminProfileData.devid,
            gAdminProfileData.devpair.pubKey,
            fakeInfo,
            DeviceStatus.Registered
        )?.let { throw it }
        deletePrereg(db, WAddress.fromParts(gAdminProfileData.wid, gServerDomain))?.let { throw it }
        db.disconnect()
    }

    /**
     * Registers a user and their first device
     */
    private fun regUser() {
        val db = DBConn()
        preregWorkspace(
            db, gUserProfileData.wid, gUserProfileData.uid, gServerDomain,
            gUserProfileData.passhash
        )?.let { throw it }
        LocalFS.get().entry(MServerPath("/ wsp ${gUserProfileData.wid}")).makeDirectory()

        val fakeInfo = CryptoString.fromString("XSALSA20:ABCDEFG1234567890")!!
        addWorkspace(
            db, gUserProfileData.wid, gUserProfileData.uid, gServerDomain,
            gUserProfileData.passhash,
            "argon2id", "anXvadxtNJAYa2cUQFqKSQ", "m=65536,t=2,p=1",
            WorkspaceStatus.Active, WorkspaceType.Individual
        )?.let { throw it }
        addDevice(
            db,
            gUserProfileData.wid,
            gUserProfileData.devid,
            gUserProfileData.devpair.pubKey,
            fakeInfo,
            DeviceStatus.Registered
        )?.let { throw it }
        deletePrereg(db, WAddress.fromParts(gUserProfileData.wid, gServerDomain))?.let { throw it }
        db.disconnect()
    }

    /**
     * Sets up keycards for both the admin and the test user
     */
    private fun setupKeycard(profile: TestProfileData) {
        val db = DBConn()

        val card = profile.keycard
        with(card.current!!) {
            isDataCompliant()?.let { throw it }
            sign("Organization-Signature", serverPrimary!!)?.let { throw it }
            addAuthString(
                "Previous-Hash",
                serverCard!!.current!!.getAuthString("Hash")!!
            )?.let { throw it }
            hash()?.let { throw it }
            sign("User-Signature", profile.crsigning)?.let { throw it }
            isCompliant()?.let { throw it }
            addEntry(db, this)?.let { throw it }
        }

        val newKeys = card.chain(profile.crsigning).getOrThrow()
        with(card.current!!) {
            sign("Organization-Signature", serverPrimary!!)?.let { throw it }
            hash()?.let { throw it }
            sign("User-Signature", profile.crsigning)?.let { throw it }
            isCompliant()?.let { throw it }
            addEntry(db, this)?.let { throw it }
        }
        assert(card.verify().getOrThrow())


        profile.data["crsigning"] =
            SigningPair.from(newKeys["crsigning.public"]!!, newKeys["crsigning.private"]!!)
        profile.data["crencryption"] =
            EncryptionPair.from(newKeys["crencryption.public"]!!, newKeys["crencryption.private"]!!)
        profile.data["signing"] =
            SigningPair.from(newKeys["signing.public"]!!, newKeys["signing.private"]!!)
        profile.data["encryption"] =
            EncryptionPair.from(newKeys["encryption.public"]!!, newKeys["encryption.private"]!!)

        db.disconnect()
    }
}


class ServerEnvironmentTest {
    @Test
    fun testBaseSetup() {
        val env = ServerTestEnvironment("servertestenv.fs").provision(SETUP_TEST_FILESYSTEM)

        val lfs = LocalFS.get()
        val rootPath = MServerPath()
        assertEquals(
            lfs.convertToLocal(rootPath).toString(),
            Paths.get(env.testPath, "topdir").toString()
        )
        assert(rootPath.toHandle().exists().getOrThrow())
        listOf("wsp", "out", "tmp", "keys").forEach {
            val path = MServerPath("/ $it")
            if (!path.toHandle().exists().getOrThrow())
                throw TestFailureException("Server workspace dir '/ $it' doesn't exist")
        }

        val exampleIPs = KCResolver.dns
            .lookupA("example.com")
            .getOrThrow()
        assertEquals(1, exampleIPs.size)
        assertEquals("/127.0.0.1", exampleIPs[0].toString())

        val oldLevel = getLogLevel()
        setLogLevel(LOG_INFO)
        logInfo("${env.testName} log test entry")
        setLogLevel(oldLevel)
    }

    @Test
    fun testBaseDBSetup() {
        ServerTestEnvironment("servertestenv.basedb")
            .provision(SETUP_TEST_DATABASE)

        // TODO: verify database setup
    }
}
