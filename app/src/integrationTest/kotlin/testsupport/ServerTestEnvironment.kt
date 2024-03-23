package testsupport

import mensagod.PGConfig
import mensagod.ServerConfig
import java.nio.file.Paths

/*
    Tests are written such that they (a) don't care about how they connect to the database, so
    long as they can and (b) don't care where in the filesystem their files are stored so long
    as they have a place to work in standard setup, so why not abstract away the details.

    Some tests will need mock server-side data and some will not. This needs to support both.
 */


/**
 * This support class is responsible for setting up the server side of anenvironment for integration
 * tests.
 */
class ServerTestEnvironment() {
    val dbconfig: PGConfig
    val serverconfig: ServerConfig
    val testPath: String

    init {
        dbconfig = PGConfig()
        serverconfig = ServerConfig.load().getOrThrow()
        testPath = Paths.get("build", "testfiles").toAbsolutePath().toString()
    }


    // Data supplied:
    // test name

    // Data needed from build environment:
    // Top folder for test
    // How to connect to Postgres
}