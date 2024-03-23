package testsupport

import libkeycard.Domain
import libkeycard.WAddress
import libmensago.MServerPath
import libmensago.resolver.KCResolver
import mensagod.*
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

/**
 * This support class is responsible for setting up the server side of anenvironment for integration
 * tests.
 */
class ServerTestEnvironment(val testName: String) {
    private val dbconfig: PGConfig = PGConfig()
    val serverconfig: ServerConfig = ServerConfig.load().getOrThrow()
    val testPath: String = Paths.get("build", "testfiles", testName).toAbsolutePath()
        .toString()

    /**
     * Provisions the test environment based on the configuration set
     */
    fun provision(provisionLevel: Int): ServerTestEnvironment {
        setupTestBase()

        return this
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
}


class ServerEnvironmentTest {
    @Test
    fun testBaseSetup() {
        val env = ServerTestEnvironment("servertestenv").provision(SETUP_TEST_FILESYSTEM)

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
}
