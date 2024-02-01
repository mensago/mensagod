package mensagod

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
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
    fun basicTest() {
        val config = ServerConfig()
        config.setValue("global.registration", "network")
        config.setValue("network.port", 9999)

        assertEquals("network", config.getString("global.registration"))
        assertEquals(9999, config.getInteger("network.port"))

        assertThrows<ClassCastException> { (config.getString("network.port")) }
        assertThrows<ClassCastException> { config.getInteger("global.registration") }

        assertNull(config.getValue("network.doesnt_exist"))
    }

    @Test
    fun loadTest() {
        // This also tests fromString()

        val testPath = makeTestFolder("serverconfig.load")
        val testConfigPath = Paths.get(testPath, "testconfig.toml")
        makeTestConfigFile(testConfigPath.toString())

        val config = ServerConfig.load(testConfigPath)
        assertEquals("private", config.getString("global.registration"))
        assertEquals(50, config.getInteger("performance.max_file_size"))
    }

    @Test
    fun toStringTest() {
        assertEquals("", ServerConfig().toString())

        val config = ServerConfig()
        config.setValue("global.registration", "network")
        config.setValue("network.port", 9999)

        val parts = listOf("[global]","""registration = "network"""", "",
            "[network]", "port = 9999", "")
        assertEquals(parts.joinToString(System.lineSeparator()), config.toString())


        // TODO: Implement ServerConfigTest::toStringTest()
    }
}