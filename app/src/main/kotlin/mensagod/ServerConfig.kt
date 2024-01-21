package mensagod

import com.moandjiezana.toml.Toml
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

fun getDefaultServerConfig(): MutableMap<String, Any> {
    return mutableMapOf(
        "database.ip" to "localhost",
        "database.port" to "5432",
        "database.name" to "mensagotest",
        "database.user" to "mensago",
        "database.password" to "",

        "global.domain" to "",
        "global.top_dir" to if (platformIsWindows) "C:\\ProgramData\\mensagodata"
                            else "/var/mensagod",
        "global.workspace_dir" to if (platformIsWindows) "C:\\ProgramData\\mensagodata\\wsp"
                            else "/var/mensagod/wsp",
        "global.registration" to "private",
        "global.registration_subnet" to "192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8, 127.0.0.1/8",
        "global.registration_subnet6" to "fe80::/10",
        "global.default_quota" to 0,
        "global.log_dir" to if (platformIsWindows) "C:\\ProgramData\\mensagod"
                            else "/etc/mensagod",

        "network.listen_ip" to "127.0.0.1",
        "network.port" to "2001",

        "performance.max_file_size" to 50,
        "performance.max_message_size" to 50,
        "performance.max_sync_age" to 7,
        "performance.max_delivery_threads" to 100,
        "performance.max_client_threads" to 10000,
        "performance.keycard_cache_size" to 5000,

        // TODO: Remove rename diceware wordcount
        "security.diceware_wordcount" to 6,
        "security.failure_delay_sec" to 3,
        "security.max_failures" to 5,
        "security.lockout_delay_min" to 15,
        "security.registration_delay_min" to 15,
        "security.password_reset_min" to 60,
    )
}


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
    val values = getDefaultServerConfig()

    /**
     * Convenience method which returns an integer as a Long. This will throw an exception if the
     * value contained by the key doesn't match.
     */
    fun getInteger(key: String): Int {
        return values[key] as Int
    }

    /**
     * Convenience method which returns a Boolean value. This will throw an exception if the
     * value contained by the key doesn't match.
     */
    fun getBool(key: String): Boolean {
        return values[key] as Boolean
    }

    /**
     * Convenience method which returns a string. This will throw an exception if the
     * value contained by the key doesn't match.
     */
    fun getString(key: String): String {
        return values[key] as String
    }

    /**
     * Connects to the database server with the settings contained in the instance.
     *
     * @throws MissingDataException if the database password is empty or otherwise missing
     * @throws java.sql.SQLException for problems connecting to the database
     */
    fun connectToDB(): Connection {
        val sb = StringBuilder("jdbc:postgresql://")
        sb.append(getString("database.ip") + ":" + getString("database.port"))
        sb.append("/" + getString("database.name"))

        val args = Properties()
        args["user"] = getString("database.user")

        if (getString("database.password").isEmpty())
            throw MissingDataException("Database password must not be empty")
        args["password"] = getString("database.password")

        val out = DriverManager.getConnection(sb.toString(), args)

        return out
    }

    /**
     * Saves the values of object to a file. If the verbose flag is true, then the method also
     * includes helpful information for users to understand the file and its settings.
     */
    fun save(path: Path, verbose: Boolean) {
        TODO("Implement ServerConfig::save()")
    }

    /**
     *  validate() performs a schema check on the configuration. If values are missing or invalid,
     *  it will return an error with a message suitable for displaying to the user.
     */
    fun validate(): String? {
        val intKeys = listOf(
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
            if (values[item.first] !is Int)
                return numMsg
            val numValue = values[item.first] as Int
            if (numValue < item.second || numValue > item.third)
                return numMsg
        }

        val stringKeys = listOf("database.ip", "database.port", "database.name", "database.user",
            "database.password", "global.domain", "global.top_dir", "global.workspace_dir",
            "global.registration", "global.registration_subnet", "global.registration_subnet6",
            "global.log_dir", "network.listen_ip", "network.port")

        for (key in stringKeys) {
            if (values[key] !is String)
                return "$key must be a string"

            if ((values[key] as String).isEmpty()) {
                if (key == "global.domain" || key == "database.password")
                    return "$key is missing or empty in the settings file and must be set."

                return "Settings variable $key is empty in the settings file. "+
                        "It may not be empty if it exists."
            }
        }

        // TODO: Validate string keys in ServerConfig::validate()

        return null
    }

    companion object {

        /**
         * Loads the global server config from a file. If not specified, it will load the file
         * C:\ProgramData\mensagod\serverconfig.toml on Windows and /etc/mensagod/serverconfig.toml
         * on other platforms.
         *
         * @throws FileNotFoundException when the specified config file is not found
         */
        fun load(path: Path? = null): ServerConfig {
            val configFilePath = path ?: if (platformIsWindows)
                Paths.get("C:\\ProgramData\\mensagod\\serverconfig.toml")
            else
                Paths.get("/etc/mensagod/serverconfig.toml")

            if (!configFilePath.exists())
                throw FileNotFoundException("Server config file not found")

            val toml = Toml().read(Files.readString(configFilePath))

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

            serverConfigSingleton = out
            return out
       }

        /**
         * Returns the global server config object. Note that if load() is not called beforehand,
         * the ServerConfig will only contain default values.
         */
        fun get(): ServerConfig { return serverConfigSingleton }
    }
}
