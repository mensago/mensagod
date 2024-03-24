package mensagod

import org.junit.jupiter.api.Test
import testsupport.SETUP_TEST_FILESYSTEM
import testsupport.ServerTestEnvironment
import java.nio.file.Paths

class LoggingTest {

    @Test
    fun basicTest() {
        val env = ServerTestEnvironment("logging.basicTest")
            .provision(SETUP_TEST_FILESYSTEM)

        // TODO: Re-enable assertThrows in LoggingTest once upgraded to Gradle 8.7
//        assertThrows<NullPointerException> { log("Uninitialized logging") }

        val testLogPath = Paths.get(env.testPath, "testlog.txt")
        initLogging(testLogPath, true)
        log("This is a test.")
        log("This is a test, too.")

        shutdownLogging()
//        assertThrows<NullPointerException> { log("Uninitialized logging") }

        env.done()
    }
}
