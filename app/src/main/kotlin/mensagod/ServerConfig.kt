package mensagod

import com.moandjiezana.toml.Toml
import keznacl.BadValueException
import keznacl.toFailure
import keznacl.toSuccess
import libkeycard.BadFieldValueException
import libkeycard.Domain
import libkeycard.MissingDataException
import libmensago.InvalidPathException
import libmensago.ResourceNotFoundException
import java.net.InetAddress
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.sql.Connection
import java.sql.DriverManager
import java.util.*
import kotlin.io.path.exists

val platformIsWindows = System.getProperty("os.name").startsWith("windows", true)
private var serverConfigSingleton = ServerConfig()

/**
 * A accessor class which loads up configuration information for mensagod on the local system. To
 * use, just instantiate the class itself and start using the info in the 'values' property.
 *
 * Because the server config file doesn't (and won't) nest tables, we only handle single-level
 * tables. We convert table values to tablename.valuename notation in the map keys.
 *
 * The ServerConfig class exists because TOML documents as provided by the parser library are
 * read-only. For ease-of-use reasons, our setup calls have side effects and can add values to
 * support calls later on.
 */
class ServerConfig {
    private val values = mutableMapOf<String, Any>()

    /**
     * Connects to the database server with the settings contained in the instance.
     *
     * @throws MissingDataException if the database password is empty or otherwise missing
     * @throws java.sql.SQLException for problems connecting to the database
     */
    fun connectToDB(): Result<Connection> {
        val sb = StringBuilder("jdbc:postgresql://")
        sb.append(getString("database.host") + ":" + getInteger("database.port"))
        sb.append("/" + getString("database.name"))

        val args = Properties()
        args["user"] = getString("database.user")

        if (getString("database.password")!!.isEmpty())
            return MissingDataException("Database password must not be empty").toFailure()
        args["password"] = getString("database.password")

        return runCatching {
            DriverManager.getConnection(sb.toString(), args).toSuccess()
        }.getOrElse { it.toFailure() }
    }

    /**
     * Returns a value in the configuration. If given a key that doesn't exist, null is returned.
     */
    fun getValue(key: String): Any? {
        return values[key] ?: defaultConfig[key]
    }

    /**
     * Convenience method which returns an integer as a Long. This will throw an exception if the
     * value type contained by the key doesn't match. Like getValue(), this method will return null
     * if the key itself doesn't exist.
     *
     * @throws ClassCastException If an integer is requested for a non-integer field
     */
    fun getInteger(key: String): Int? {
        return getValue(key) as Int?
    }

    /**
     * Convenience method which returns a string. This will throw an exception if the
     * value type contained by the key doesn't match. Like getValue(), this method will return null
     * if the key itself doesn't exist.
     *
     * @throws ClassCastException If an string is requested for a non-string field
     */
    fun getString(key: String): String? {
        return getValue(key) as String?
    }

    /**
     * Reverts a field to its default value. This method actually throws exceptions, unlike most
     * of the class.
     *
     * @throws BadValueException If the key specified is invalid.
     */
    fun resetValue(key: String) {
        if (!isValidKey(key)) throw BadValueException()
        values.remove(key)
    }

    /**
     * Sets a value in the configuration. Keys are expected to be in the format tablename.fieldname.
     *
     * @throws BadValueException Returned if the key specified is invalid.
     * @throws BadFieldValueException Returned if the value is more than 1K characters
     */
    fun setValue(key: String, value: Any): Throwable? {
        if (!isValidKey(key)) return BadValueException()
        if (value is String && value.length > 1024) return BadFieldValueException()
        values[key] = value
        return null
    }

    /**
     * Converts the object to a string containing only values which are different from the default.
     *
     * @throws BadValueException if a key is not in the format table.fieldname
     */
    override fun toString(): String {
        val tree = makeValueTree()

        val sl = mutableListOf<String>()
        for (key in orderedKeys) {
            if (tree[key] != null) {
                if (sl.size > 0)
                    sl.add("")
                sl.add("[$key]")
            } else continue

            for (field in orderedKeyLists[key]!!) {
                if (!tree[key]!!.containsKey(field)) continue

                when (val data = tree[key]!![field]!!) {
                    is Boolean -> {
                        val boolStr = if (data) "True" else "False"
                        sl.add("$field = $boolStr")
                    }

                    is Int -> sl.add("$field = $data")
                    else -> sl.add("""$field = "$data"""")
                }
            }
        }
        sl.add("")

        return sl.joinToString(System.lineSeparator())
    }

    /**
     * Converts the object to a heavily-commented string which contains helpful information for
     * users. This is generally the better choice over toString() when saving the instance's
     * comments to a file.
     *
     * @throws BadValueException Returned if a key is not in the format table.fieldname
     */
    fun toVerboseString(): Result<String> {
        val makeValueString = fun(key: String): String {
            // We can throw here because if it crashes, it's a developer screw-up and will be
            // caught by a unit test.
            if (!isValidKey(key)) throw BadValueException()

            val value = values[key] ?: return ""
            val parts = key.split(".")

            return when (value) {
                is Boolean -> {
                    val boolStr = if (value) "True" else "False"
                    "${parts[1]} = $boolStr"
                }

                is Int -> "${parts[1]} = $value"
                else -> """${parts[1]} = "$value""""
            }
        }

        val sep = System.lineSeparator()

        val sl = mutableListOf<String>()

        // Database section

        sl.addAll(
            listOf(
                "# This is a Mensago server config file. Each value listed below is the",
                "# default value. Every effort has been made to set this file to sensible",
                "# defaults to keep things simple. This file is expected to be found in",
                "# /etc/mensagod/serverconfig.toml or C:\\ProgramData\\mensagod on Windows.",
                "",
                "[database]",
                "# Settings needed for connecting to the database.",
                "#",
                """# host = "localhost"""",
                """# port = 5432""",
                """# name = "mensago"""",
                """# user = "mensago"""",
            )
        )
        makeValueString("database.host").let { if (it.isNotEmpty()) sl.add(it) }
        makeValueString("database.port").let { if (it.isNotEmpty()) sl.add(it) }
        makeValueString("database.name").let { if (it.isNotEmpty()) sl.add(it) }
        makeValueString("database.user").let { if (it.isNotEmpty()) sl.add(it) }
        sl.add("""password = "${getString("database.password")}"""")

        // Global section

        sl.addAll(
            listOf(
                "$sep[global]",
                """domain = "${getString("global.domain")}"""",
                "",
                "# The location where user data is stored. The default for Windows is",
                """# "C:\\ProgramData\\mensago", but for other platforms is "/var/mensagod".""",
                """# top_dir = "/var/mensagod""""
            )
        )
        makeValueString("global.top_dir").let { if (it.isNotEmpty()) sl.add(it) }

        sl.addAll(
            listOf(
                "$sep# The type of registration. 'public' is open to outside registration requests,",
                "# and would be appropriate only for hosting a public free server. 'moderated'",
                "# is open to public registration, but an administrator must approve the request",
                "# before an account can be created. 'network' limits registration to a",
                "# specified subnet or IP address. 'private' permits account registration only",
                "# by an administrator. For most situations 'private' is the appropriate setting.",
                """# registration = "private"""",
            )
        )
        makeValueString("global.registration").let { if (it.isNotEmpty()) sl.add(it) }

        sl.addAll(
            listOf(
                "$sep# For servers configured to network registration, this variable sets the",
                "# subnet(s) to which account registration is limited. Subnets are expected to",
                "# be in CIDR notation and comma-separated. The default setting restricts",
                "# registration to the private (non-routable) networks.",
                """# registration_subnet = "192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8, 127.0.0.1/8"""",
                """# registration_subnet6 = "fe80::/10"""",
            )
        )
        makeValueString("global.registration_subnet").let { if (it.isNotEmpty()) sl.add(it) }
        makeValueString("global.registration_subnet6").let { if (it.isNotEmpty()) sl.add(it) }

        sl.add("$sep# The default storage quota for a workspace, measured in MiB. 0 means no limit.")
        sl.add("# default_quota = 0")
        makeValueString("global.default_quota").let { if (it.isNotEmpty()) sl.add(it) }

        sl.addAll(
            listOf(
                "$sep# Location for log files. This directory requires full permissions for the",
                "# user mensagod runs as. On Windows, this defaults to the same location as the",
                "# server config file, i.e. C:\\ProgramData\\mensagod",
                """# log_dir = "/var/mensagod"""",
            )
        )
        makeValueString("global.log_dir").let { if (it.isNotEmpty()) sl.add(it) }

        sl.addAll(
            listOf(
                "$sep[network]",
                "# The interface and port to listen on",
                """# listen_ip = "127.0.0.1"""",
                "# port = 2001",
            )
        )
        makeValueString("network.listen_ip").let { if (it.isNotEmpty()) sl.add(it) }
        makeValueString("network.port").let { if (it.isNotEmpty()) sl.add(it) }

        sl.addAll(
            listOf(
                "$sep[performance]",
                "# Items in this section are for performance tuning. They are set to defaults",
                "# which should work for most environments. Care should be used when changing",
                "# any of these values.",
                "# ",
                "# The maximum size in MiB of a file stored on the server. Note that this is",
                "# the size of the actual data stored on disk. Encoding adds 25% overhead.",
                "# max_file_size = 50",
            )
        )
        makeValueString("performance.max_file_size").let { if (it.isNotEmpty()) sl.add(it) }

        sl.addAll(
            listOf(
                "$sep# The maximum size in MiB of a message. The value of max_file_size takes",
                "# precedence if this value is larger than the value of max_file_size.",
                "# max_message_size = 50",
            )
        )
        makeValueString("performance.max_message_size").let { if (it.isNotEmpty()) sl.add(it) }

        sl.addAll(
            listOf(
                "$sep# Max age of sync records in days. Any records older than the oldest device",
                "# login timestamp minus this number of days are purged. Defaults to 6 months,",
                "# which should be plenty.",
                "# max_sync_age = 360",
            )
        )
        makeValueString("performance.max_sync_age").let { if (it.isNotEmpty()) sl.add(it) }

        sl.addAll(
            listOf(
                "$sep# The maximum number of worker threads created handle delivering messages,",
                "# both internally and externally",
                "# max_delivery_threads = 100",
            )
        )
        makeValueString("performance.max_delivery_threads").let { if (it.isNotEmpty()) sl.add(it) }

        sl.addAll(
            listOf(
                "$sep# The maximum number of client worker threads. Be careful in changing this",
                "# number -- if it is too low, client devices many not be able to connect",
                "# and messages may not be delivered from outside the organization, and if it",
                "# is set too high, client demand may overwhelm the server.",
                "# max_client_threads = 10000",
            )
        )
        makeValueString("performance.max_client_threads").let { if (it.isNotEmpty()) sl.add(it) }

        sl.addAll(
            listOf(
                "$sep# The maximum number of keycards to keep in the in-memory cache. This number",
                "# has a direct effect on the server's memory usage, so adjust this with care.",
                "# keycard_cache_size = 5000",
            )
        )
        makeValueString("performance.keycard_cache_size").let { if (it.isNotEmpty()) sl.add(it) }

        sl.addAll(
            listOf(
                "$sep[security]",
                "# The number of words used in a registration code. 6 is recommended for best",
                "# security in most situations. This value cannot be less than 3.",
                "# diceware_wordcount = 6",
            )
        )
        makeValueString("security.diceware_wordcount").let { if (it.isNotEmpty()) sl.add(it) }

        sl.addAll(
            listOf(
                "$sep# The number of seconds to wait after a login failure before accepting another",
                "# attempt",
                "# failure_delay_sec = 3",
            )
        )
        makeValueString("security.failure_delay_sec").let { if (it.isNotEmpty()) sl.add(it) }

        sl.addAll(
            listOf(
                "$sep# The number of login failures made before a connection is closed. ",
                "# max_failures = 5",
            )
        )
        makeValueString("security.max_failures").let { if (it.isNotEmpty()) sl.add(it) }

        sl.addAll(
            listOf(
                "$sep# The number of minutes the client must wait after reaching max_failures",
                "# before another attempt may be made. Note that additional attempts to login",
                "# prior to the completion of this delay resets the timeout.",
                "# lockout_delay_min = 15",
            )
        )
        makeValueString("security.lockout_delay_min").let { if (it.isNotEmpty()) sl.add(it) }

        sl.addAll(
            listOf(
                "$sep# The delay, in minutes, between account registration requests from the same",
                "# IP address. This is to prevent registration spam.",
                "# registration_delay_min = 15",
            )
        )
        makeValueString("security.registration_delay_min").let { if (it.isNotEmpty()) sl.add(it) }

        sl.addAll(
            listOf(
                "$sep# The amount of time, in minutes, a password reset code is valid. It must be",
                "# at least 10 and no more than 2880 (48 hours).",
                "# password_reset_min = 60",
            )
        )
        makeValueString("security.password_reset_min").let { if (it.isNotEmpty()) sl.add(it) }

        sl.add("")

        return sl.joinToString(System.lineSeparator()).toSuccess()
    }

    /**
     *  validate() performs a schema check on the configuration. If values are missing or invalid,
     *  it will return an error with a message suitable for displaying to the user.
     */
    fun validate(): String? {
        val intKeys = listOf(
            Triple("database.port", 1, 65535),
            Triple("global.default_quota", 0, 1_000_000_000),
            Triple("network.port", 1, 65535),
            Triple("performance.max_file_size", 1, 1024),
            Triple("performance.max_message_size", 1, 1024),
            Triple("performance.max_sync_age", 1, 365),
            Triple("performance.max_delivery_threads", 1, 1_000_000),
            Triple("performance.max_client_threads", 1, 1_000_000),
            Triple("performance.keycard_cache_size", 1, 1_000_000),

            Triple("security.diceware_wordcount", 3, 25),
            Triple("security.failure_delay_sec", 1, 300),
            Triple("security.max_failures", 3, 100),
            Triple("security.lockout_delay_min", 1, 1440),
            Triple("security.registration_delay_min", 1, 1440),
            Triple("security.password_reset_min", 10, 10_080),
        )

        for (item in intKeys) {
            val numMsg = "${item.first} must be a number from ${item.second} through ${item.third}"
            if (getValue(item.first) !is Int)
                return numMsg
            val numValue = getInteger(item.first)!!
            if (numValue < item.second || numValue > item.third)
                return numMsg
        }

        val stringKeys = listOf(
            "database.host", "database.name", "database.user",
            "database.password", "global.domain", "global.top_dir", "global.workspace_dir",
            "global.registration", "global.registration_subnet", "global.registration_subnet6",
            "global.log_dir", "network.listen_ip"
        )

        for (key in stringKeys) {
            if (getValue(key) !is String)
                return "$key must be a string"

            if (getString(key)!!.isEmpty()) {
                if (key == "global.domain" || key == "database.password")
                    return "$key is missing or empty in the settings file and must be set."

                return "Settings variable $key is empty in the settings file. " +
                        "It may not be empty if it exists."
            }
        }

        // String fields which are locations
        listOf("global.top_dir", "global.workspace_dir", "global.log_dir").forEach {
            if (values[it] != null) {
                val path = try {
                    Paths.get(values[it]!! as String)
                } catch (e: InvalidPathException) {
                    return "Invalid path '${values[it]}' for setting $it."
                }

                if (!path.exists())
                    return "Path '${values[it]}' for setting $it doesn't exist."
            }
        }

        // One-off string fields

        if (values["network.listen_ip"] != null) {
            try {
                InetAddress.getByName(values["network.listen_ip"]!! as String)
            } catch (e: Exception) {
                return "Invalid address for setting network.listen_ip"
            }
        }

        if (values["database.host"] != null) {
            try {
                InetAddress.getByName(values["database.host"]!! as String)
            } catch (e: Exception) {
                return "Invalid or unknown host for setting database.host"
            }
        }

        if (Domain.fromString(values["global.domain"] as String?) == null)
            return "Invalid global.domain value '${values["global.domain"]}'"

        listOf("global.registration_subnet", "global.registration_subnet6").forEach { subnetField ->
            if (values[subnetField] != null) {
                (values[subnetField]!! as String)
                    .split(",")
                    .map { it.trim() }
                    .filter { it.isNotEmpty() }
                    .forEach {
                        CIDRUtils.fromString(it)
                            ?: return "Invalid subnet '$it' in setting $subnetField"
                    }
            }
        }

        if (values["global.registration"] != null &&
            !listOf("private", "network", "moderated", "public")
                .contains(values["global.registration"])
        )
            return "Registration mode must be 'private', 'network', 'moderated', or 'public'."

        // Free-form fields which are skipped
        //
        // database.name
        // database.user
        // database.password

        return null
    }

    private fun isValidKey(key: String): Boolean {
        val parts = key.trim().split(".")
        return (parts.size == 2 && orderedKeys.contains(parts[0]) &&
                orderedKeyLists[parts[0]]!!.contains(parts[1]))
    }

    /**
     * Converts the internal format of the ServerConfig instance to a format much more suitable for
     * export.
     *
     * @throws BadValueException if a key is not in the format table.fieldname
     */
    private fun makeValueTree(): MutableMap<String, MutableMap<String, Any>> {
        val tree = mutableMapOf<String, MutableMap<String, Any>>()
        values.keys.forEach { key ->
            val parts = key.trim().split(".")
            if (parts.size != 2) throw BadValueException("Bad settings key $key")

            if (tree[parts[0]] == null) tree[parts[0]] = mutableMapOf()
            tree[parts[0]]!![parts[1]] = values[key]!!
        }
        return tree
    }

    companion object {

        /**
         * Returns a ServerConfig object from the supplied string data.
         *
         * @throws IllegalStateException If the TOML data is invalid
         */
        fun fromString(data: String): ServerConfig {
            val toml = Toml().read(data)

            val out = ServerConfig()
            toml.entrySet().forEach { entry ->
                val table = toml.getTable(entry.key)
                table.entrySet().forEach { tableItem ->
                    val mapKey = "${entry.key}.${tableItem.key}"

                    when (tableItem.value) {
                        is Boolean -> out.values[mapKey] = tableItem.value as Boolean
                        is Long -> out.values[mapKey] = tableItem.value as Long
                        else -> out.values[mapKey] = tableItem.value.toString()
                    }
                }
            }
            return out
        }

        /**
         * Returns the global server config object. Note that if load() is not called beforehand,
         * the ServerConfig will only contain default values.
         */
        fun get(): ServerConfig {
            return serverConfigSingleton
        }

        /**
         * Loads the global server config from a file. If not specified, it will load the file
         * C:\ProgramData\mensagod\serverconfig.toml on Windows and /etc/mensagod/serverconfig.toml
         * on other platforms.
         *
         * @throws ResourceNotFoundException when the specified config file is not found
         * @throws IllegalStateException If the TOML data is invalid
         */
        fun load(path: Path? = null): Result<ServerConfig> {
            val configFilePath = path ?: if (platformIsWindows)
                Paths.get("C:\\ProgramData\\mensagod\\serverconfig.toml")
            else
                Paths.get("/etc/mensagod/serverconfig.toml")

            if (!configFilePath.exists())
                return ResourceNotFoundException("Server config file not found").toFailure()

            val out = fromString(Files.readString(configFilePath))
            serverConfigSingleton = out
            return out.toSuccess()
        }

        private val defaultConfig = mutableMapOf<String, Any>(
            "database.host" to "localhost",
            "database.port" to 5432,
            "database.name" to "mensagotest",
            "database.user" to "mensago",
            "database.password" to "",

            "global.domain" to "",
            "global.top_dir" to if (
                System.getProperty("os.name").startsWith("windows", true))
                "C:\\ProgramData\\mensagodata"
            else "/var/mensagod",
            "global.workspace_dir" to if (
                System.getProperty("os.name").startsWith("windows", true))
                "C:\\ProgramData\\mensagodata\\wsp"
            else "/var/mensagod/wsp",
            "global.registration" to "private",
            "global.registration_subnet" to "192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8, 127.0.0.1/8",
            "global.registration_subnet6" to "fe80::/10",
            "global.default_quota" to 0,
            "global.log_dir" to if (
                System.getProperty("os.name").startsWith("windows", true))
                "C:\\ProgramData\\mensagod"
            else "/etc/mensagod",

            "network.listen_ip" to "127.0.0.1",
            "network.port" to 2001,

            "performance.max_file_size" to 50,
            "performance.max_message_size" to 50,
            "performance.max_sync_age" to 360,
            "performance.max_delivery_threads" to 100,
            "performance.max_client_threads" to 10000,
            "performance.keycard_cache_size" to 5000,

            "security.diceware_wordcount" to 6,
            "security.failure_delay_sec" to 3,
            "security.max_failures" to 5,
            "security.lockout_delay_min" to 15,
            "security.registration_delay_min" to 15,
            "security.password_reset_min" to 60,
        )
    }
}

// For saving to a file
private val orderedKeys = listOf("global", "database", "network", "performance", "security")
private val orderedKeyLists = mapOf(
    "global" to listOf(
        "domain", "top_dir", "workspace_dir", "registration", "registration_subnet",
        "registration_subnet6", "default_quota", "log_dir", "listen_ip", "port"
    ),
    "database" to listOf("host", "port", "name", "user", "password"),
    "network" to listOf("listen_ip", "port"),
    "performance" to listOf(
        "max_file_size", "max_message_size", "max_sync_age",
        "max_delivery_threads", "max_client_threads", "keycard_cache_size"
    ),
    "security" to listOf(
        "diceware_wordcount", "failure_delay_sec", "max_failures",
        "lockout_delay_min", "registration_delay_min", "password_reset_min"
    )
)
