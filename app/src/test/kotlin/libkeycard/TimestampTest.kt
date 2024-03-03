package libkeycard

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class TimestampTest {

    @Test
    fun timestampTest() {
        assertNull(Timestamp.fromString("foobar"))

        val ts = Timestamp.fromString("2022-05-01T13:10:11Z")
        assertNotNull(ts)
        assertEquals("2022-05-01T13:10:11Z", ts.toString())
        assertEquals("2022-05-01", ts!!.toDateString())
        assertEquals("2022-05-02T13:10:11Z", ts.plusDays(1).toString())

        val ds = Timestamp.fromDateString("2022-05-02")
        assertNotNull(ds)
        assertEquals("2022-05-02", ds!!.toDateString())
        assertEquals("2022-05-02T00:00:00Z", ds.toString())

        val lts = Timestamp()
        assertEquals(20, lts.formatted.length)

        assert(Timestamp.checkFormat("2022-05-02T00:00:00Z"))
        assert(!Timestamp.checkFormat("2022-05-02"))
    }
}
