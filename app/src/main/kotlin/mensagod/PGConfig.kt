package mensagod

import java.sql.Connection
import java.sql.DriverManager
import java.util.*

/**
 * Class containing the necessary information to connect to the database which the server sits on
 * top of.
 */
data class PGConfig(
    var user: String = "mensago",
    var password: String = "",
    var host: String = "localhost",
    var port: Int = 5432,
    var dbname: String = "mensago"
) {
    fun connect(): Result<Connection> {
        return kotlin.runCatching { DriverManager.getConnection(getURL(), getArgs()) }
    }

    fun getURL(): String {
        return "jdbc:postgresql://$host:$port/$dbname"
    }

    fun getArgs(): Properties {
        return Properties().apply {
            this["user"] = user
            this["password"] = password
        }
    }
}
