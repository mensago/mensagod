package testsupport

import keznacl.BadValueException
import keznacl.EmptyDataException
import mensagod.PGConfig
import java.sql.Connection
import java.sql.PreparedStatement
import java.sql.ResultSet
import java.sql.Statement
import java.util.concurrent.atomic.AtomicInteger


private val dbCount = AtomicInteger(0)

/**
 * The PGConn class is a stripped-down version of the DBConn class found in mensagod. It is designed
 * specifically for test environments and, as such, dispenses with Result handling because tests
 * that crash aren't just not a big deal, they're actually helpful.
 */
class PGConn(connConfig: PGConfig) {
    private var conn: Connection = connConfig.connect().getOrThrow()
    private var batch: Statement? = null

    fun query(q: String, vararg args: Any): ResultSet {
        if (q.isEmpty()) throw EmptyDataException()
        val stmt = prepStatement(q, args)
        return stmt.executeQuery()
    }

    fun execute(s: String, vararg args: Any): Int? {
        if (s.isEmpty()) throw EmptyDataException()
        val stmt = prepStatement(s, args)
        stmt.execute()
        val count = stmt.updateCount
        return if (count < 0) null else count
    }

    fun add(s: String) {
        if (s.isEmpty()) throw EmptyDataException()

        if (batch == null)
            batch = conn.createStatement()
        batch!!.addBatch(s)
    }

    fun executeBatch() {
        if (batch == null) throw EmptyDataException()
        batch!!.executeBatch()
        batch = null
    }

    fun exists(q: String, vararg args: Any): Boolean {
        if (q.isEmpty()) throw EmptyDataException()
        return prepStatement(q, args).executeQuery().next()
    }

    private fun prepStatement(s: String, args: Array<out Any>): PreparedStatement {
        // Make sure the ? count in s matches the number of args
        val qCount = s.split("?").size - 1
        if (qCount != args.size)
            throw BadValueException(
                "Parameter count $qCount does not match number of placeholders"
            )

        val out = conn.prepareStatement(s)
        for (i in 0 until qCount) {
            when (args[i]::class.simpleName) {
                "ByteArray" -> out.setBytes(i + 1, args[i] as ByteArray)
                "Boolean" -> out.setBoolean(i + 1, args[i] as Boolean)
                "Int" -> out.setInt(i + 1, args[i] as Int)
                "Long" -> out.setLong(i + 1, args[i] as Long)
                else -> out.setString(i + 1, args[i].toString())
            }
        }
        return out
    }
}
