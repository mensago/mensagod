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
    }

    @Test
    fun toVerboseStringTest1() {
        val config = ServerConfig()
        val expected =
            """# This is a Mensago server config file. Each value listed below is the
            |# default value. Every effort has been made to set this file to sensible
            |# defaults to keep things simple. This file is expected to be found in
            |# /etc/mensagod/serverconfig.toml or C:\ProgramData\mensagod on Windows.
            |
            |[database]
            |# Settings needed for connecting to the database.
            |#
            |# ip = "localhost"
            |# port = 5432
            |# name = "mensago"
            |# user = "mensago"
            |password = ""
            |
            |[global]
            |domain = ""
            |
            |# The location where user data is stored. The default for Windows is
            |# "C:\\ProgramData\\mensago", but for other platforms is "/var/mensagod".
            |# top_dir = "/var/mensagod"
            |
            |# The type of registration. 'public' is open to outside registration requests,
            |# and would be appropriate only for hosting a public free server. 'moderated'
            |# is open to public registration, but an administrator must approve the request
            |# before an account can be created. 'network' limits registration to a
            |# specified subnet or IP address. 'private' permits account registration only
            |# by an administrator. For most situations 'private' is the appropriate setting.
            |# registration = "private"
            |
            |# For servers configured to network registration, this variable sets the
            |# subnet(s) to which account registration is limited. Subnets are expected to
            |# be in CIDR notation and comma-separated. The default setting restricts
            |# registration to the private (non-routable) networks.
            |# registration_subnet = "192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8, 127.0.0.1/8"
            |# registration_subnet6 = "fe80::/10"
            |
            |# The default storage quota for a workspace, measured in MiB. 0 means no limit.
            |# default_quota = 0
            |
            |# Location for log files. This directory requires full permissions for the
            |# user mensagod runs as. On Windows, this defaults to the same location as the
            |# server config file, i.e. C:\ProgramData\mensagod
            |# top_dir = "/var/mensagod"
            |""".trimMargin()

        assertEquals(expected, config.toVerboseString())
    }
}
