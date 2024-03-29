package mensagod

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import java.sql.SQLException

class DBConnTest {

    @Test
    fun connectionTests() {
        val config = ServerConfig.load().getOrThrow()
        resetDB(config).getOrThrow()
        DBConn.initialize(config)?.let { throw it }
        val db = DBConn().connect().getOrThrow()

        assert(db.isConnected())
        db.disconnect()?.let { throw it }
        assert(!db.isConnected())
        db.connect().getOrThrow()
        assert(db.isConnected())
        db.disconnect()
    }

    @Test
    fun execute() {
        val config = ServerConfig.load().getOrThrow()
        resetDB(config).getOrThrow()
        DBConn.initialize(config)?.let { throw it }
        val db = DBConn().connect().getOrThrow()

        db.execute(
            """CREATE TABLE testtable(
                    rowid SERIAL PRIMARY KEY,
                    wid VARCHAR(36) NOT NULL UNIQUE, userid VARCHAR(64));"""
        ).getOrThrow()
        db.execute("""INSERT INTO testtable(wid,userid) VALUES('foo', 'bar');""").getOrThrow()
        assert(db.execute("CREATE ;").exceptionOrNull() is SQLException)

        val rs = db.query("SELECT wid,userid FROM testtable;").getOrThrow()

        assert(rs.next())
        assertEquals("foo", rs.getString(1))
        assertEquals("bar", rs.getString(2))

        assert(db.exists("SELECT wid,userid FROM testtable;").getOrThrow())
        assertFalse(db.exists("SELECT wid FROM testtable WHERE wid='bar';").getOrThrow())

        db.disconnect()?.let { throw it }
    }

    @Test
    fun batch() {
        val config = ServerConfig.load().getOrThrow()
        resetDB(config).getOrThrow()
        DBConn.initialize(config)?.let { throw it }
        val db = DBConn().connect().getOrThrow()

        db.execute(
            """CREATE TABLE testtable(
                    rowid SERIAL PRIMARY KEY,
                    wid VARCHAR(36) NOT NULL UNIQUE, userid VARCHAR(64));"""
        ).getOrThrow()

        db.add("""INSERT INTO testtable(wid,userid) VALUES('foo1', 'bar1');""")?.let { throw it }
        db.add("""INSERT INTO testtable(wid,userid) VALUES('foo2', 'bar2');""")?.let { throw it }
        db.add("""INSERT INTO testtable(wid,userid) VALUES('foo3', 'bar3');""")?.let { throw it }
        db.executeBatch()?.let { throw it }

        val rs = db.query("SELECT COUNT(*) FROM testtable;").getOrThrow()
        assert(rs.next())
        assertEquals(3, rs.getInt(1))
        db.disconnect()
    }
}