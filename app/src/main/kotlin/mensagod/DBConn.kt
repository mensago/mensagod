package mensagod

import keznacl.*
import libkeycard.MissingDataException
import libmensago.NotConnectedException
import java.sql.*
import java.util.*

//private val dbCount = AtomicInteger(0)

/**
 * The DBConn class is a frontend to the storage database for the application. It provides an
 * interface to the storage medium which abstracts away the specific type of database and the
 * details needed to connect to it. It also makes interaction with the Java database API a little
 * easier.
 */
class DBConn(val connConfig: PGConfig? = null) {
    private var conn: Connection? = null
    private var batch: Statement? = null

    init {
        connect().getOrThrow()
    }

    /**
     * Connects to the server with the information specified in initialize()
     *
     * @throws EmptyDataException if called before initialize()
     * @throws java.sql.SQLException if there are problems connecting to the database
     */
    fun connect(): Result<DBConn> {
        // No sense in creating a new connection if we're already connected
        if (conn != null) return this.toSuccess()

        if (connConfig != null) {
            conn = connConfig.connect().getOrElse { return it.toFailure() }
            return this.toSuccess()
        }

        if (dbURL.isEmpty()) return EmptyDataException().toFailure()

        conn = kotlin.runCatching {
            if (dbArgs.isNotEmpty()) DriverManager.getConnection(dbURL, dbArgs)
            else DriverManager.getConnection(dbURL)
        }.getOrElse { return it.toFailure() }

//        println("DB connected: ${dbCount.addAndGet(1)}")
        return this.toSuccess()
    }

    /**
     * Disconnects from the database
     *
     * @throws java.sql.SQLException if there are problems disconnecting from the database
     */
    fun disconnect(): Throwable? {
        return try {
            if (conn != null) {
//                println("DB disconnected: ${dbCount.addAndGet(-1)}")
                conn!!.close()
            }
            conn = null
            null
        } catch (e: Exception) {
            e
        }
    }

    fun isConnected(): Boolean {
        return conn != null
    }

    fun getConnection(): Connection? {
        return conn
    }

    /**
     * Executes a query to the database
     *
     * @throws EmptyDataException if your query is empty
     * @throws NotConnectedException if not connected to the database
     * @throws BadValueException if the query placeholder count doesn't match the query argument count
     * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
     */
    fun query(q: String, vararg args: Any): Result<ResultSet> {
        if (q.isEmpty()) return EmptyDataException().toFailure()
        if (!isConnected()) return NotConnectedException().toFailure()

        val stmt = prepStatement(q, args).getOrElse { return it.toFailure() }
        return runCatching { stmt.executeQuery().toSuccess() }.getOrElse { it.toFailure() }
    }

    /**
     * Executes a single command on the database
     *
     * @throws EmptyDataException if your query is empty
     * @throws NotConnectedException if not connected to the database
     * @throws BadValueException if the query placeholder count doesn't match the query argument count
     * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
     */
    fun execute(s: String, vararg args: Any): Result<Int?> {
        if (s.isEmpty()) return EmptyDataException().toFailure()
        if (!isConnected()) return NotConnectedException().toFailure()

        val stmt = prepStatement(s, args).getOrElse { return it.toFailure() }
        return runCatching {
            stmt.execute()
            val count = stmt.updateCount
            return Result.success(if (count < 0) null else count)
        }.getOrElse {
            it.toFailure()
        }
    }

    /**
     * Adds a command to the internal list of handlers to be executed in batch
     *
     * @throws EmptyDataException if your query is empty
     * @throws NotConnectedException if not connected to the database
     * @throws BadValueException if the query placeholder count doesn't match the query argument count
     * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
     */
    fun add(s: String): Throwable? {
        if (s.isEmpty()) return EmptyDataException()
        if (!isConnected()) return NotConnectedException()

        return runCatching {
            if (batch == null)
                batch = conn!!.createStatement()
            batch!!.addBatch(s)
            null
        }.getOrElse {
            it
        }
    }

    /**
     * Runs all handlers in the internal list created with add()
     *
     * @throws EmptyDataException if your query is empty
     * @throws NotConnectedException if not connected to the database
     * @throws BadValueException if the query placeholder count doesn't match the query argument count
     * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
     */
    fun executeBatch(): Throwable? {
        if (!isConnected()) return NotConnectedException()
        if (batch == null) return EmptyDataException()
        return runCatching {
            batch!!.executeBatch()
            batch = null
            null
        }.getOrElse {
            it
        }
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
    fun exists(q: String, vararg args: Any): Result<Boolean> {
        if (q.isEmpty()) return EmptyDataException().toFailure()
        if (!isConnected()) return NotConnectedException().toFailure()

        return runCatching {
            val stmt = prepStatement(q, args).getOrThrow()
            val rs = stmt.executeQuery()
            rs.next().toSuccess()
        }.getOrElse {
            it.toFailure()
        }
    }

    /**
     * Convenience method which creates a prepared statement. It expects data of one of three
     * types: ByteArray, Boolean, or something convertible to a string.
     *
     * @throws BadValueException if the query placeholder count doesn't match the query argument count
     * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
     */
    private fun prepStatement(s: String, args: Array<out Any>): Result<PreparedStatement> {

        // Make sure the ? count in s matches the number of args
        val qCount = s.split("?").size - 1
        if (qCount != args.size)
            return BadValueException(
                "Parameter count $qCount does not match number of placeholders"
            ).toFailure()

        // This is an internal call for query() and execute(). The null check is done there.
        return try {
            val out = conn!!.prepareStatement(s)
            for (i in 0 until qCount) {
                when (args[i]::class.simpleName) {
                    "ByteArray" -> out.setBytes(i + 1, args[i] as ByteArray)
                    "Boolean" -> out.setBoolean(i + 1, args[i] as Boolean)
                    "Int" -> out.setInt(i + 1, args[i] as Int)
                    "Long" -> out.setLong(i + 1, args[i] as Long)
                    else -> out.setString(i + 1, args[i].toString())
                }
            }
            out.toSuccess()
        } catch (e: Exception) {
            e.toFailure()
        }
    }

    companion object {
        private var dbURL = ""
        private var dbArgs = Properties()

        /**
         * This sets up easy access to the database server so that other parts of the server can
         * just focus on connecting and interacting with the database. It also performs a
         * connection test to confirm all is well.
         *
         * @throws MissingDataException if the database password is empty or missing
         * @throws java.sql.SQLException if there are problems connecting to the database
         */
        fun initialize(config: ServerConfig): Throwable? {
            config.getString("database.password").onNullOrEmpty {
                return MissingDataException("Database password must not be empty")
            }

            val pgc = PGConfig(
                config.getString("database.user")!!,
                config.getString("database.password")!!,
                config.getString("database.host")!!,
                config.getInteger("database.port")!!,
                config.getString("database.name")!!
            )

            pgc.connect().getOrElse { return it }.close()

            dbURL = pgc.getURL()
            dbArgs = pgc.getArgs()
            return null
        }
    }
}

/**
 * Block function to run short sections requiring a database connection that also return
 * a value.
 *
 * @exception DatabaseException Returned if there is a problem connecting to the database
 */
inline fun <V> withDBResult(block: (db: DBConn) -> V): Result<V> {
    val db =
        runCatching { DBConn() }.getOrElse { return Result.failure(DatabaseException()) }
    val out = block(db)
    db.disconnect()
    return Result.success(out)
}

/**
 * Block function to run short sections requiring a database connection.
 *
 * @return Indicates success connecting to the database. False indicates a problem.
 * @exception DatabaseException Returned if there is a problem connecting to the database
 */
inline fun withDB(block: (db: DBConn) -> Unit): Boolean {
    val db = runCatching { DBConn() }.getOrElse { return false }
    block(db)
    db.disconnect()
    return true
}

