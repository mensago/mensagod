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
        val url = "jdbc:postgresql://$host:$port/$dbname"
        val args = Properties()
        with(args) {
            this["user"] = user
            this["password"] = password
        }
        return kotlin.runCatching { DriverManager.getConnection(url, args) }
    }
}
