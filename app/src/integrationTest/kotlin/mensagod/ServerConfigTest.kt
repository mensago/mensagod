package mensagod

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import testsupport.TestFailureException
import testsupport.makeTestFolder
import java.io.File
import java.nio.file.Paths

class ServerConfigTest {

    private fun makeTestConfigFile(path: String) {
        val handle = File(path)
        handle.writeText(
            """
[database]
name = "mensago"
password = "S3cr3tPa55w*rd"

[global]
domain = "example.com"
top_dir = "/var/mensagod"
registration = "private"

"""
        )
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

        val config = ServerConfig.load(testConfigPath).getOrThrow()
        assertEquals("private", config.getString("global.registration"))
        assertEquals(50, config.getInteger("performance.max_file_size"))
    }

    @Test
    fun toStringTest() {
        assertEquals("", ServerConfig().toString())

        val config = ServerConfig()
        config.setValue("global.registration", "network")
        config.setValue("network.port", 9999)

        val parts = listOf(
            "[global]", """registration = "network"""", "",
            "[network]", "port = 9999", ""
        )
        assertEquals(parts.joinToString(System.lineSeparator()), config.toString())
    }

    @Test
    fun toVerboseStringTest1() {
        // This test is for checking the output of an empty ServerConfig()
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
            |# host = "localhost"
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
            |# log_dir = "/var/mensagod"
            |
            |[network]
            |# The interface and port to listen on
            |# listen_ip = "127.0.0.1"
            |# port = 2001
            |
            |[performance]
            |# Items in this section are for performance tuning. They are set to defaults
            |# which should work for most environments. Care should be used when changing
            |# any of these values.
            |# 
            |# The maximum size in MiB of a file stored on the server. Note that this is
            |# the size of the actual data stored on disk. Encoding adds 25% overhead.
            |# max_file_size = 50
            |
            |# The maximum size in MiB of a message. The value of max_file_size takes
            |# precedence if this value is larger than the value of max_file_size.
            |# max_message_size = 50
            |
            |# Max age of sync records in days. Any records older than the oldest device
            |# login timestamp minus this number of days are purged. Defaults to 6 months,
            |# which should be plenty.
            |# max_sync_age = 360
            |
            |# The maximum number of worker threads created handle delivering messages,
            |# both internally and externally
            |# max_delivery_threads = 100
            |
            |# The maximum number of client worker threads. Be careful in changing this
            |# number -- if it is too low, client devices many not be able to connect
            |# and messages may not be delivered from outside the organization, and if it
            |# is set too high, client demand may overwhelm the server.
            |# max_client_threads = 10000
            |
            |# The maximum number of keycards to keep in the in-memory cache. This number
            |# has a direct effect on the server's memory usage, so adjust this with care.
            |# keycard_cache_size = 5000
            |
            |[security]
            |# The number of words used in a registration code. 6 is recommended for best
            |# security in most situations. This value cannot be less than 3.
            |# diceware_wordcount = 6
            |
            |# The number of seconds to wait after a login failure before accepting another
            |# attempt
            |# failure_delay_sec = 3
            |
            |# The number of login failures made before a connection is closed. 
            |# max_failures = 5
            |
            |# The number of minutes the client must wait after reaching max_failures
            |# before another attempt may be made. Note that additional attempts to login
            |# prior to the completion of this delay resets the timeout.
            |# lockout_delay_min = 15
            |
            |# The delay, in minutes, between account registration requests from the same
            |# IP address. This is to prevent registration spam.
            |# registration_delay_min = 15
            |
            |# The amount of time, in minutes, a password reset code is valid. It must be
            |# at least 10 and no more than 2880 (48 hours).
            |# password_reset_min = 60
            |""".trimMargin()

        if (expected != config.toVerboseString().getOrThrow()) {
            println("Expected:\n-------------")
            println("|||$expected|||")
            println("Received:\n-------------")
            println("|||${config.toVerboseString().getOrThrow()}|||")
            throw TestFailureException("ServerConfig comparison failure")
        }
    }

    @Test
    fun toVerboseStringTest2() {
        // This test is for the output of a ServerConfig where every value has been changed
        val config = ServerConfig()
        config.run {
            setValue("database.host", "localhost2")
            setValue("database.port", 1234)
            setValue("database.name", "mensago2")
            setValue("database.user", "mensago2")
            setValue("database.password", "foobar")

            setValue("global.domain", "example.com")
            setValue("global.top_dir", "/")
            setValue("global.registration", "network")
            setValue("global.registration_subnet", "192.168.0.0/16")
            setValue("global.registration_subnet6", "fe80::/12")
            setValue("global.default_quota", 5000)
            setValue("global.log_dir", "/var/log/mensagod")

            setValue("network.listen_ip", "192.168.0.1")
            setValue("network.port", 4321)

            setValue("performance.max_file_size", 100)
            setValue("performance.max_message_size", 100)
            setValue("performance.max_sync_age", 14)
            setValue("performance.max_delivery_threads", 200)
            setValue("performance.max_client_threads", 20000)
            setValue("performance.keycard_cache_size", 6000)

            setValue("security.diceware_wordcount", 5)
            setValue("security.failure_delay_sec", 5)
            setValue("security.max_failures", 10)
            setValue("security.lockout_delay_min", 30)
            setValue("security.registration_delay_min", 30)
            setValue("security.password_reset_min", 120)
        }

        val expected =
            """# This is a Mensago server config file. Each value listed below is the
            |# default value. Every effort has been made to set this file to sensible
            |# defaults to keep things simple. This file is expected to be found in
            |# /etc/mensagod/serverconfig.toml or C:\ProgramData\mensagod on Windows.
            |
            |[database]
            |# Settings needed for connecting to the database.
            |#
            |# host = "localhost"
            |# port = 5432
            |# name = "mensago"
            |# user = "mensago"
            |host = "localhost2"
            |port = 1234
            |name = "mensago2"
            |user = "mensago2"
            |password = "foobar"
            |
            |[global]
            |domain = "example.com"
            |
            |# The location where user data is stored. The default for Windows is
            |# "C:\\ProgramData\\mensago", but for other platforms is "/var/mensagod".
            |# top_dir = "/var/mensagod"
            |top_dir = "/"
            |
            |# The type of registration. 'public' is open to outside registration requests,
            |# and would be appropriate only for hosting a public free server. 'moderated'
            |# is open to public registration, but an administrator must approve the request
            |# before an account can be created. 'network' limits registration to a
            |# specified subnet or IP address. 'private' permits account registration only
            |# by an administrator. For most situations 'private' is the appropriate setting.
            |# registration = "private"
            |registration = "network"
            |
            |# For servers configured to network registration, this variable sets the
            |# subnet(s) to which account registration is limited. Subnets are expected to
            |# be in CIDR notation and comma-separated. The default setting restricts
            |# registration to the private (non-routable) networks.
            |# registration_subnet = "192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8, 127.0.0.1/8"
            |# registration_subnet6 = "fe80::/10"
            |registration_subnet = "192.168.0.0/16"
            |registration_subnet6 = "fe80::/12"
            |
            |# The default storage quota for a workspace, measured in MiB. 0 means no limit.
            |# default_quota = 0
            |default_quota = 5000
            |
            |# Location for log files. This directory requires full permissions for the
            |# user mensagod runs as. On Windows, this defaults to the same location as the
            |# server config file, i.e. C:\ProgramData\mensagod
            |# log_dir = "/var/mensagod"
            |log_dir = "/var/log/mensagod"
            |
            |[network]
            |# The interface and port to listen on
            |# listen_ip = "127.0.0.1"
            |# port = 2001
            |listen_ip = "192.168.0.1"
            |port = 4321
            |
            |[performance]
            |# Items in this section are for performance tuning. They are set to defaults
            |# which should work for most environments. Care should be used when changing
            |# any of these values.
            |# 
            |# The maximum size in MiB of a file stored on the server. Note that this is
            |# the size of the actual data stored on disk. Encoding adds 25% overhead.
            |# max_file_size = 50
            |max_file_size = 100
            |
            |# The maximum size in MiB of a message. The value of max_file_size takes
            |# precedence if this value is larger than the value of max_file_size.
            |# max_message_size = 50
            |max_message_size = 100
            |
            |# Max age of sync records in days. Any records older than the oldest device
            |# login timestamp minus this number of days are purged. Defaults to 6 months,
            |# which should be plenty.
            |# max_sync_age = 360
            |max_sync_age = 14
            |
            |# The maximum number of worker threads created handle delivering messages,
            |# both internally and externally
            |# max_delivery_threads = 100
            |max_delivery_threads = 200
            |
            |# The maximum number of client worker threads. Be careful in changing this
            |# number -- if it is too low, client devices many not be able to connect
            |# and messages may not be delivered from outside the organization, and if it
            |# is set too high, client demand may overwhelm the server.
            |# max_client_threads = 10000
            |max_client_threads = 20000
            |
            |# The maximum number of keycards to keep in the in-memory cache. This number
            |# has a direct effect on the server's memory usage, so adjust this with care.
            |# keycard_cache_size = 5000
            |keycard_cache_size = 6000
            |
            |[security]
            |# The number of words used in a registration code. 6 is recommended for best
            |# security in most situations. This value cannot be less than 3.
            |# diceware_wordcount = 6
            |diceware_wordcount = 5
            |
            |# The number of seconds to wait after a login failure before accepting another
            |# attempt
            |# failure_delay_sec = 3
            |failure_delay_sec = 5
            |
            |# The number of login failures made before a connection is closed. 
            |# max_failures = 5
            |max_failures = 10
            |
            |# The number of minutes the client must wait after reaching max_failures
            |# before another attempt may be made. Note that additional attempts to login
            |# prior to the completion of this delay resets the timeout.
            |# lockout_delay_min = 15
            |lockout_delay_min = 30
            |
            |# The delay, in minutes, between account registration requests from the same
            |# IP address. This is to prevent registration spam.
            |# registration_delay_min = 15
            |registration_delay_min = 30
            |
            |# The amount of time, in minutes, a password reset code is valid. It must be
            |# at least 10 and no more than 2880 (48 hours).
            |# password_reset_min = 60
            |password_reset_min = 120
            |""".trimMargin()

        if (expected != config.toVerboseString().getOrThrow()) {
            println("Expected:\n-------------")
            println("|||$expected|||")
            println("Received:\n-------------")
            println("|||${config.toVerboseString().getOrThrow()}|||")
            throw TestFailureException("ServerConfig comparison failure")
        }
    }

    @Test
    fun validateTest() {
        val config = ServerConfig()

        // First, test the required values: db password and org's domain

        assertNotNull(config.validate())
        config.setValue("database.password", "foobar")
        assertNotNull(config.validate())
        config.setValue("global.domain", "example/com")
        assertNotNull(config.validate())
        config.setValue("global.domain", "example.com")
        assertNull(config.validate())

        // Test type checking along with other stuff

        config.setValue("database.host", true)
        assertNotNull(config.validate())
        config.setValue("database.host", "www.eff.org")
        assertNull(config.validate())
        config.setValue("database.host", "192.168.0.1")
        assertNull(config.validate())

        config.setValue("database.port", true)
        assertNotNull(config.validate())
        config.resetValue("database.port")

        // database.name, .user, and .password are freeform fields and don't need validated

        // Technically, it's possible these paths could actually pass, but the chance is remote.
        if (platformIsWindows)
            config.setValue("global.top_dir", "C:\\0a8f7b99-1ca7-4b15-9cbf-e962c8f515ca/")
        else
            config.setValue("global.top_dir", "/0a8f7b99-1ca7-4b15-9cbf-e962c8f515ca")
        assertNotNull(config.validate())

        if (platformIsWindows)
            config.setValue("global.top_dir", "C:\\")
        else
            config.setValue("global.top_dir", "/etc")
        assertNull(config.validate())

        config.setValue("global.registration", "foobar")
        assertNotNull(config.validate())
        config.setValue("global.registration", "moderated")
        assertNull(config.validate())

        config.setValue("global.registration_subnet", "abcdefg")
        assertNotNull(config.validate())
        config.setValue("global.registration_subnet", "172.16.0.0/12, 10.0.0.0/8")
        assertNull(config.validate())

        config.setValue("global.registration_subnet6", "abcdefg")
        assertNotNull(config.validate())
        config.setValue("global.registration_subnet6", "fe80::/15")
        assertNull(config.validate())

        config.setValue("global.default_quota", 2_000_000_000)
        assertNotNull(config.validate())
        config.setValue("global.default_quota", 100)
        assertNull(config.validate())

        if (platformIsWindows)
            config.setValue("global.log_dir", "C:\\")
        else
            config.setValue("global.log_dir", "/etc")
        assertNull(config.validate())

        config.setValue("network.listen_ip", "abcdefg")
        assertNotNull(config.validate())
        config.setValue("network.listen_ip", "172.16.16.16")
        assertNull(config.validate())

        config.setValue("network.port", 100_000)
        assertNotNull(config.validate())
        config.setValue("network.port", 100)
        assertNull(config.validate())

        listOf(
            "performance.max_file_size", "performance.max_message_size",
            "performance.max_sync_age", "performance.max_delivery_threads",
            "performance.max_client_threads", "performance.keycard_cache_size"
        ).forEach {
            config.setValue(it, 100_000_000)
            assertNotNull(config.validate())
            config.setValue(it, 30)
            assertNull(config.validate())
        }

        config.setValue("security.diceware_wordcount", 100)
        assertNotNull(config.validate())
        config.setValue("security.diceware_wordcount", 8)
        assertNull(config.validate())

        listOf(
            "security.failure_delay_sec", "security.max_failures",
            "security.lockout_delay_min", "security.registration_delay_min",
            "security.password_reset_min"
        ).forEach {
            config.setValue(it, 100_000_000)
            assertNotNull(config.validate())
            config.setValue(it, 60)
            assertNull(config.validate())
        }
    }
}
