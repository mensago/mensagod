package mensagod

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import testsupport.makeTestFolder
import java.nio.file.Paths

class LoggingTest {

    @Test
    fun basicTest() {
        val testPath = makeTestFolder("logging.basicTest")
        assertThrows<NullPointerException> { log("Uninitialized logging") }

        val testLogPath = Paths.get(testPath, "testlog.txt")
        initLogging(testLogPath, true)
        log("This is a test.")

        shutdownLogging()
        assertThrows<NullPointerException> { log("Uninitialized logging") }
    }
}
