package mensagod

import keznacl.BadValueException
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class MServerPathTest {

    @Test
    fun basicTest() {
        var path = MServerPath()
        Assertions.assertNull(path.set("/"))

        Assertions.assertNull(path.set("/ 725cd0ed-1135-46aa-837e-5bdfb809763a"))
        assert(path.isDir())

        Assertions.assertNull(path.set(
            "/ 725cd0ed-1135-46aa-837e-5bdfb809763a 123467.1000.4c51a8b2-d8c1-4589-8543-36e038fee403"))
        assert(path.isFile())

        assertEquals("123467.1000.4c51a8b2-d8c1-4589-8543-36e038fee403", path.basename())
        assertEquals("/ 725cd0ed-1135-46aa-837e-5bdfb809763a", path.parent()!!.get())
        assert(MServerPath().isRoot())

        path = MServerPath()
        path.push("11111111-1111-1111-1111-111111111111")
        assertEquals("/ 11111111-1111-1111-1111-111111111111", path.get())

        assert(path.set("/abc\b/def") is BadValueException)
    }

    @Test
    fun basicTest2() {

        // Success cases
        listOf(
            "/",
            "/ wsp",
            "/ tmp",
            "/ out",
            "/ wsp fa0423e9-da5c-4927-a8f2-0274b38045bf a1b20c58-26fd-4d29-9f76-3408edd9cdb4 " +
                    "d665a6c9-6248-478c-89a8-0d5953c3c077",
            "/ wsp fa0423e9-da5c-4927-a8f2-0274b38045bf a1b20c58-26fd-4d29-9f76-3408edd9cdb4 " +
                    "12345.1000.d665a6c9-6248-478c-89a8-0d5953c3c077",
            "/ fa0423e9-da5c-4927-a8f2-0274b38045bf"
        ).forEach { Assertions.assertNotNull(MServerPath.fromString(it)) }

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
        ).forEach { Assertions.assertNull(MServerPath.fromString(it)) }
    }

    @Test
    fun buildTest() {

        Assertions.assertEquals(null, MServerPath.fromString("/")!!.parent())
        Assertions.assertEquals("/", MServerPath.fromString("/ wsp")!!.parent()!!.toString())
        Assertions.assertEquals(
            "/ wsp", MServerPath.fromString(
                "/ wsp fa0423e9-da5c-4927-a8f2-0274b38045bf"
            )!!.parent().toString()
        )

        Assertions.assertEquals("/", MServerPath.fromString("/")!!.basename())
        Assertions.assertEquals("wsp", MServerPath.fromString("/ wsp")!!.basename())

        assert(!MServerPath.fromString(
            "/ wsp fa0423e9-da5c-4927-a8f2-0274b38045bf")!!.isFile())
        assert(MServerPath.fromString(
            "/ wsp fa0423e9-da5c-4927-a8f2-0274b38045bf")!!.isDir())

        assert(MServerPath.fromString(
            "/ wsp fa0423e9-da5c-4927-a8f2-0274b38045bf " +
                    "12345.1000.d665a6c9-6248-478c-89a8-0d5953c3c077")!!.isFile())
        assert(!MServerPath.fromString(
            "/ wsp fa0423e9-da5c-4927-a8f2-0274b38045bf " +
                    "12345.1000.d665a6c9-6248-478c-89a8-0d5953c3c077")!!.isDir())
    }
}