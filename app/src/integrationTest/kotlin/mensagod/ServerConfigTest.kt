package mensagod

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import java.io.File
import java.nio.file.Paths

class ServerConfigTest {

    private fun makeTestConfigFile(path: String) {
        val handle = File(path)
        handle.writeText("""
[database]
name = "mensago"
password = "S3cr3tPa55w*rd"

[global]
domain = "example.com"
top_dir = "/var/mensagod"
registration = "private"

""")
    }

    @Test
    fun loadTest() {
        val testPath = makeTestFolder("serverconfig.load")
        val testConfigPath = Paths.get(testPath, "testconfig.toml")
        makeTestConfigFile(testConfigPath.toString())

        val config = ServerConfig.load(testConfigPath)
        config.values["testbool"] = false
        assertEquals("private", config.getString("global.registration"))
        assertEquals(50, config.getInteger("performance.max_file_size"))
        assertFalse(config.getBool("testbool"))
    }
}