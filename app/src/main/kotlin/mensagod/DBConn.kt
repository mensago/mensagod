package mensagod

import keznacl.BadValueException
import keznacl.EmptyDataException
import libkeycard.MissingDataException
import java.sql.*
import java.util.*

private var dbURL = ""
private var dbArgs = Properties()

/**
 * The DBConn class is a frontend to the storage database for the application. It provides an
 * interface to the storage medium which abstracts away the specific type of database and the
 * details needed to connect to it. It also makes interaction with the Java database API a little
 * easier.
 */
class DBConn {
    private var conn: Connection? = null
    private var batch: Statement? = null

    init {
        connect()
    }

    /**
     * Connects to the server with the information specified in initialize()
     *
     * @throws EmptyDataException if called before initialize()
     * @throws java.sql.SQLException if there are problems connecting to the database
     */
    fun connect(): DBConn {
        if (dbURL.isEmpty()) throw EmptyDataException()

        // No sense in creating a new connection if we're already connected
        if (conn != null) return this

        conn = if (dbArgs.isNotEmpty()) DriverManager.getConnection(dbURL, dbArgs)
            else DriverManager.getConnection(dbURL)
        return this
    }

    /**
     * Disconnects from the database
     *
     * @throws java.sql.SQLException if there are problems disconnecting from the database
     */
    fun disconnect() {
        if (conn != null) { conn!!.close() }
        conn = null
    }

    fun isConnected(): Boolean {
        return conn != null
    }

    fun getConnection(): Connection? { return conn }

    /**
     * Executes a query to the database
     *
     * @throws EmptyDataException if your query is empty
     * @throws NotConnectedException if not connected to the database
     * @throws BadValueException if the query placeholder count doesn't match the query argument count
     * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
     */
    fun query(q: String, vararg args: Any): ResultSet {
        if (q.isEmpty()) throw EmptyDataException()
        if (!isConnected()) throw NotConnectedException()

        val stmt = prepStatement(q, args)
        return stmt.executeQuery()
    }

    /**
     * Executes a single command on the database
     *
     * @throws EmptyDataException if your query is empty
     * @throws NotConnectedException if not connected to the database
     * @throws BadValueException if the query placeholder count doesn't match the query argument count
     * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
     */
    fun execute(s: String, vararg args: Any) {
        if (s.isEmpty()) throw EmptyDataException()
        if (!isConnected()) throw NotConnectedException()

        val stmt = prepStatement(s, args)
        stmt.execute()
    }

    /**
     * Adds a command to the internal list of commands to be executed in batch
     *
     * @throws EmptyDataException if your query is empty
     * @throws NotConnectedException if not connected to the database
     * @throws BadValueException if the query placeholder count doesn't match the query argument count
     * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
     */
    fun add(s: String) {
        if (s.isEmpty()) throw EmptyDataException()
        if (!isConnected()) throw NotConnectedException()

        if (batch == null)
            batch = conn!!.createStatement()
        batch!!.addBatch(s)
    }

    /**
     * Runs all commands in the internal list created with add()
     *
     * @throws EmptyDataException if your query is empty
     * @throws NotConnectedException if not connected to the database
     * @throws BadValueException if the query placeholder count doesn't match the query argument count
     * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
     */
    fun executeBatch() {
        if (!isConnected()) throw NotConnectedException()
        if (batch == null) throw EmptyDataException()
        batch!!.executeBatch()
        batch = null
    }

    /**
     * Checks to see if at least one row is returned for a query. It expects usage of SELECT because
     * a database may not necessarily support COUNT().
     *
     * @throws EmptyDataException if your query is empty
     * @throws NotConnectedException if not connected to the database
     * @throws BadValueException if the query placeholder count doesn't match the query argument count
     * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
     */
    fun exists(q: String, vararg args: Any): Boolean {
        if (q.isEmpty()) throw EmptyDataException()
        if (!isConnected()) throw NotConnectedException()

        val stmt = prepStatement(q, args)
        val rs = stmt.executeQuery()
        return rs.next()
    }

    /**
     * Convenience method which creates a prepared statement. It expects data of one of three
     * types: ByteArray, Boolean, or something convertible to a string.
     *
     * @throws BadValueException if the query placeholder count doesn't match the query argument count
     * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
     */
    private fun prepStatement(s: String, args: Array<out Any>): PreparedStatement {

        // Make sure the ? count in s matches the number of args
        val qCount = s.split("?").size - 1
        if (qCount != args.size)
            throw BadValueException(
                "Parameter count $qCount does not match number of placeholders")

        // This is an internal call for query() and execute(). The null check is done there.
        val out = conn!!.prepareStatement(s)

        for (i in 0 until qCount) {
            when(args[i]::class.simpleName) {
                "ByteArray" -> out.setBytes(i+1, args[i] as ByteArray)
                "Boolean" -> out.setBoolean(i+1, args[i] as Boolean)
                else -> out.setString(i+1, args[i].toString())
            }
        }

        return out
    }

    companion object {

        /**
         * This sets up easy access to the database server so that other parts of the server can
         * just focus on connecting and interacting with the database. It also performs a
         * connection test to confirm all is well.
         *
         * @throws MissingDataException if the database password is empty or missing
         * @throws java.sql.SQLException if there are problems connecting to the database
         */
        fun initialize(config: ServerConfig) {
            val sb = StringBuilder("jdbc:postgresql://")
            sb.append(config.getString("database.ip") + ":" +
                    config.getInteger("database.port").toString())
            sb.append("/" + config.getString("database.name"))

            val args = Properties()
            args["user"] = config.getString("database.user")

            if (config.getString("database.password")?.isEmpty() == true)
                throw MissingDataException("Database password must not be empty")
            args["password"] = config.getString("database.password")

            val url = sb.toString()
            DriverManager.getConnection(url, args)

            dbURL = url
            dbArgs = args
        }
    }
}
