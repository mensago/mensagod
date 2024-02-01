package mensagod

import com.moandjiezana.toml.Toml
import keznacl.BadValueException
import libkeycard.MissingDataException
import java.io.FileNotFoundException
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
    private val values = mutableMapOf<String,Any>()

    /**
     * Connects to the database server with the settings contained in the instance.
     *
     * @throws MissingDataException if the database password is empty or otherwise missing
     * @throws java.sql.SQLException for problems connecting to the database
     */
    fun connectToDB(): Connection {
        val sb = StringBuilder("jdbc:postgresql://")
        sb.append(getString("database.ip") + ":" + getInteger("database.port"))
        sb.append("/" + getString("database.name"))

        val args = Properties()
        args["user"] = getString("database.user")

        if (getString("database.password")!!.isEmpty())
            throw MissingDataException("Database password must not be empty")
        args["password"] = getString("database.password")

        val out = DriverManager.getConnection(sb.toString(), args)

        return out
    }

    /**
     * Returns a value in the configuration. If given a key that doesn't exist, null is returned.
     */
    fun getValue(key: String): Any? { return values[key] ?: defaultConfig[key] }

    /**
     * Convenience method which returns an integer as a Long. This will throw an exception if the
     * value type contained by the key doesn't match. Like getValue(), this method will return null
     * if the key itself doesn't exist.
     *
     * @throws ClassCastException If an integer is requested for a non-integer field
     */
    fun getInteger(key: String): Int? { return getValue(key) as Int? }

    /**
     * Convenience method which returns a string. This will throw an exception if the
     * value type contained by the key doesn't match. Like getValue(), this method will return null
     * if the key itself doesn't exist.
     *
     * @throws ClassCastException If an string is requested for a non-string field
     */
    fun getString(key: String): String? { return getValue(key) as String? }

    /**
     * Sets a value in the configuration. Keys are expected to be in the format tablename.fieldname.
     *
     * @throws BadValueException If the key specified is invalid.
     */
    fun setValue(key: String, value: Any) {
        if (!isValidKey(key)) throw BadValueException()
        values[key] = value
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
     * @throws BadValueException if a key is not in the format table.fieldname
     */
    fun toVerboseString(): String {
        val makeValueString = fun (key: String): String {
            if (!isValidKey(key)) throw BadValueException()

            val value = values[key] ?: return ""
            val parts = key.split(".")

            when (value) {
                is Boolean -> {
                    val boolStr = if (value) "True" else "False"
                    return "${parts[1]} = $boolStr" + System.lineSeparator()
                }
                is Int -> return "${parts[1]} = $value" + System.lineSeparator()
                else -> return """${parts[1]} = "$value"""" + System.lineSeparator()
            }
        }

        val sep = System.lineSeparator()

        val sl = mutableListOf<String>()

        // Database section

        sl.add(
        """# This is a Mensago server config file. Each value listed below is the
                |# default value. Every effort has been made to set this file to sensible
                |# defaults to keep things simple. This file is expected to be found in
                |# /etc/mensagod/serverconfig.toml or C:\ProgramData\mensagod on Windows.
                |
                |[database]
                |# Settings needed for connecting to the database.
                |#
                |# ip = "localhost"
                |# port = "5432"
                |# name = "mensago"
                |# user = "mensago"
                |""".trimMargin()
        )
        sl.add(makeValueString("database.ip"))
        sl.add(makeValueString("database.port"))
        sl.add(makeValueString("database.name"))
        sl.add(makeValueString("database.user"))
        sl.add("""database.password = "${getString("database.password")}"$sep""")

        // Global section

        sl.add(
            """$sep[global]
            |domain = "${getString("global.domain")}"
            |
            |# The location where user data is stored. The default for Windows is 
            |# "C:\\ProgramData\\mensago", but for other platforms is "/var/mensagod".
            |# top_dir = "/var/mensagod"
            |""".trimMargin()
        )
        sl.add(makeValueString("global.top_dir"))
        sl.add(
            """# The type of registration. 'public' is open to outside registration requests,
            |# and would be appropriate only for hosting a public free server. 'moderated'
            |# is open to public registration, but an administrator must approve the request
            |# before an account can be created. 'network' limits registration to a 
            |# specified subnet or IP address. 'private' permits account registration only
            |# by an administrator. For most situations 'private' is the appropriate setting.
            |# registration = "private"
            |""".trimMargin()
        )
        sl.add(makeValueString("global.registration"))

        sl.add(
            """# For servers configured to network registration, this variable sets the 
            |# subnet(s) to which account registration is limited. Subnets are expected to
            |# be in CIDR notation and comma-separated. The default setting restricts
            |# registration to the private (non-routable) networks.
            |# registration_subnet = "192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8, 127.0.0.1/8"
            |# registration_subnet6 = "fe80::/10"
            |""".trimIndent()
        )
        sl.add(makeValueString("global.registration_subnet"))
        sl.add(makeValueString("global.registration_subnet6"))

        // TODO: Finish toVerboseString()

        return sl.joinToString("")
    }

    /**
     *  validate() performs a schema check on the configuration. If values are missing or invalid,
     *  it will return an error with a message suitable for displaying to the user.
     */
    fun validate(): String? {
        val intKeys = listOf(
            Triple("network.port", 1, 65535),
            Triple("database.port", 1, 65535),
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

        val stringKeys = listOf("database.ip", "database.name", "database.user",
            "database.password", "global.domain", "global.top_dir", "global.workspace_dir",
            "global.registration", "global.registration_subnet", "global.registration_subnet6",
            "global.log_dir", "network.listen_ip")

        for (key in stringKeys) {
            if (getValue(key) !is String)
                return "$key must be a string"

            if (getString(key)!!.isEmpty()) {
                if (key == "global.domain" || key == "database.password")
                    return "$key is missing or empty in the settings file and must be set."

                return "Settings variable $key is empty in the settings file. "+
                        "It may not be empty if it exists."
            }
        }

        // TODO: Validate string keys in ServerConfig::validate()

        return null
    }

    private fun isValidKey(key: String): Boolean {
        val parts = key.trim().split(".")
        return (parts.size == 2 && orderedKeys.contains(parts[0]) &&
            orderedKeyLists[parts[0]]!!.contains(parts[1]) )
    }

    /**
     * Converts the internal format of the ServerConfig instance to a format much more suitable for
     * export.
     *
     * @throws BadValueException if a key is not in the format table.fieldname
     */
    private fun makeValueTree(): MutableMap<String,MutableMap<String,Any>> {
        val tree = mutableMapOf<String,MutableMap<String,Any>>()
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

                    when (tableItem.value){
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
        fun get(): ServerConfig { return serverConfigSingleton }

        /**
         * Loads the global server config from a file. If not specified, it will load the file
         * C:\ProgramData\mensagod\serverconfig.toml on Windows and /etc/mensagod/serverconfig.toml
         * on other platforms.
         *
         * @throws FileNotFoundException when the specified config file is not found
         * @throws IllegalStateException If the TOML data is invalid
         */
        fun load(path: Path? = null): ServerConfig {
            val configFilePath = path ?: if (platformIsWindows)
                Paths.get("C:\\ProgramData\\mensagod\\serverconfig.toml")
            else
                Paths.get("/etc/mensagod/serverconfig.toml")

            if (!configFilePath.exists())
                throw FileNotFoundException("Server config file not found")

            val out = fromString(Files.readString(configFilePath))
            serverConfigSingleton = out
            return out
       }

        private val defaultConfig = mutableMapOf<String,Any>(
            "database.ip" to "localhost",
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
            "performance.max_sync_age" to 7,
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
    "global" to listOf("domain", "top_dir", "workspace_dir", "registration", "registration_subnet",
        "registration_subnet6", "default_quota", "log_dir", "listen_ip", "port"),
    "database" to listOf("ip", "port", "name", "user", "password"),
    "network" to listOf("listen_ip", "port"),
    "performance" to listOf("max_file_size", "max_message_size", "max_sync_age",
        "max_delivery_threads", "max_client_threads", "keycard_cache_size"),
    "security" to listOf("diceware_wordcount", "failure_delay_sec", "max_failures",
        "lockout_delay_min", "registration_delay_min", "password_reset_min")
)
