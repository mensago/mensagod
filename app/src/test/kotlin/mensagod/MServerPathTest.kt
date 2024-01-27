package mensagod

import keznacl.BadValueException
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.nio.file.Paths

class MServerPathTest {

    @Test
    fun basicTest() {
        var path = MServerPath()
        assertNotNull(path.set("/"))

        assertNotNull(path.set("/ 725cd0ed-1135-46aa-837e-5bdfb809763a"))
        assert(path.isDir())

        assertNotNull(path.set(
            "/ 725cd0ed-1135-46aa-837e-5bdfb809763a 123467.1000.4c51a8b2-d8c1-4589-8543-36e038fee403"))
        assert(path.isFile())

        assertEquals("123467.1000.4c51a8b2-d8c1-4589-8543-36e038fee403", path.basename())
        assertEquals("/ 725cd0ed-1135-46aa-837e-5bdfb809763a", path.parent()!!.get())
        assert(MServerPath().isRoot())

        path = MServerPath()
        path.push("11111111-1111-1111-1111-111111111111")
        assertEquals("/ 11111111-1111-1111-1111-111111111111", path.get())

        assertNull(path.set("/abc\b/def"))
    }

    @Test
    fun basicTest2() {

        // Success cases
        listOf(
            "/",
            "/ wsp",
            "/ keys",
            "/ out",
            "/ tmp",
            "/ wsp fa0423e9-da5c-4927-a8f2-0274b38045bf a1b20c58-26fd-4d29-9f76-3408edd9cdb4 " +
                    "d665a6c9-6248-478c-89a8-0d5953c3c077",
            "/ wsp fa0423e9-da5c-4927-a8f2-0274b38045bf a1b20c58-26fd-4d29-9f76-3408edd9cdb4 " +
                    "12345.1000.d665a6c9-6248-478c-89a8-0d5953c3c077",
            "/ fa0423e9-da5c-4927-a8f2-0274b38045bf"
        ).forEach {
            if (MServerPath.fromString(it) == null)
                throw BadValueException("fromString() failure on good value $it")
        }

        // Failure cases
        listOf(
            "/ foo",
            " / tmp",
            "/ tmp ",
            "abc",
            "/ wsp abc234",
            "12345.1000.d665a6c9-6248-478c-89a8-0d5953c3c077",
            "/ wsp 12345.1000.d665a6c9-6248-478c-89a8-0d5953c3c077 " +
                    "fa0423e9-da5c-4927-a8f2-0274b38045bf",
        ).forEach { assertNull(MServerPath.fromString(it)) }
    }

    @Test
    fun buildTest() {

        assertEquals(null, MServerPath.fromString("/")!!.parent())
        assertEquals("/", MServerPath.fromString("/ wsp")!!.parent()!!.toString())
        assertEquals(
            "/ wsp", MServerPath.fromString(
                "/ wsp fa0423e9-da5c-4927-a8f2-0274b38045bf"
            )!!.parent().toString()
        )

        assertEquals("/", MServerPath.fromString("/")!!.basename())
        assertEquals("wsp", MServerPath.fromString("/ wsp")!!.basename())

        assert(!MServerPath.fromString(
            "/ wsp fa0423e9-da5c-4927-a8f2-0274b38045bf"
        )!!.isFile())
        assert(
            MServerPath.fromString(
                "/ wsp fa0423e9-da5c-4927-a8f2-0274b38045bf"
            )!!.isDir())

        assert(
            MServerPath.fromString(
                "/ wsp fa0423e9-da5c-4927-a8f2-0274b38045bf " +
                        "12345.1000.d665a6c9-6248-478c-89a8-0d5953c3c077"
            )!!.isFile())
        assert(!MServerPath.fromString(
            "/ wsp fa0423e9-da5c-4927-a8f2-0274b38045bf " +
                    "12345.1000.d665a6c9-6248-478c-89a8-0d5953c3c077"
        )!!.isDir())
    }

    @Test
    fun convertTest() {
        val converted = if (platformIsWindows)
            """\var\mensagod\wsp\d8b6d06b-7728-4c43-bc08-85a0c645d260"""
        else
            "/var/mensagod/wsp/d8b6d06b-7728-4c43-bc08-85a0c645d260"

        assertEquals(converted,
            MServerPath("/ wsp d8b6d06b-7728-4c43-bc08-85a0c645d260")
                .convertToLocal(Paths.get("/var/mensagod"))?.toString())
    }
}
