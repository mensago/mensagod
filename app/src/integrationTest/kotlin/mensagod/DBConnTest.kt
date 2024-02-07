package mensagod

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.sql.SQLException

class DBConnTest {

    @Test
    fun connectionTests() {
        val config = ServerConfig.load().getOrThrow()
        resetDB(config).getOrThrow()
        DBConn.initialize(config)
        val db = DBConn().connect()

        assert(db.isConnected())
        db.disconnect()
        assert(!db.isConnected())
        db.connect()
        assert(db.isConnected())
    }

    @Test
    fun execute() {
        val config = ServerConfig.load().getOrThrow()
        resetDB(config).getOrThrow()
        DBConn.initialize(config)
        val db = DBConn().connect()

        db.execute("""CREATE TABLE testtable(
                    rowid SERIAL PRIMARY KEY,
                    wid VARCHAR(36) NOT NULL UNIQUE, userid VARCHAR(64));""")
        db.execute("""INSERT INTO testtable(wid,userid) VALUES('foo', 'bar');""")
        assertThrows<SQLException> { db.execute("CREATE ;") }

        val rs = db.query("SELECT wid,userid FROM testtable;")

        assert(rs.next())
        assertEquals("foo", rs.getString(1))
        assertEquals("bar", rs.getString(2))

        assert(db.exists("SELECT wid,userid FROM testtable;"))
        assertFalse(db.exists("SELECT wid FROM testtable WHERE wid='bar';"))

        db.disconnect()
    }

    @Test
    fun batch() {
        val config = ServerConfig.load().getOrThrow()
        resetDB(config).getOrThrow()
        DBConn.initialize(config)
        val db = DBConn().connect()

        db.execute("""CREATE TABLE testtable(
                    rowid SERIAL PRIMARY KEY,
                    wid VARCHAR(36) NOT NULL UNIQUE, userid VARCHAR(64));""")

        db.add("""INSERT INTO testtable(wid,userid) VALUES('foo1', 'bar1');""")
        db.add("""INSERT INTO testtable(wid,userid) VALUES('foo2', 'bar2');""")
        db.add("""INSERT INTO testtable(wid,userid) VALUES('foo3', 'bar3');""")
        db.executeBatch()

        val rs = db.query("SELECT COUNT(*) FROM testtable;")
        assert(rs.next())
        assertEquals(3, rs.getInt(1))
    }
}