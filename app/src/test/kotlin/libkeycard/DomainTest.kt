package libkeycard

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class DomainTest {

    @Test
    fun domainTests() {
        // Test the basics
        assertNotNull(Domain.fromString("foo-bar"))
        assertNotNull(Domain.fromString("foo-bar.baz.com"))

        assertEquals("foo.bar.com", Domain.fromString("FOO.bar.com")!!.value)

        assertNull(Domain.fromString("a bad-id.com"))
        assertNull(Domain.fromString("also_bad.org"))

        // parent() testing

        assertNotNull(Domain.fromString("foo-bar.baz.com")!!.parent())
        assertNull(Domain.fromString("baz.com")!!.parent())

        assertEquals("baz.com", Domain.fromString("foo-bar.baz.com")!!.parent())

        // push() and pop()

        val dom = Domain.fromString("baz.com")!!
        assert(dom.push("foo.bar"))
        assertEquals("foo.bar.baz.com", dom.value)
        assert(dom.pop())
        assertEquals("bar.baz.com", dom.value)
        assert(dom.pop())
        assertEquals("baz.com", dom.value)
        assert(dom.pop())
        assertEquals("com", dom.value)
        assert(dom.pop())
        assertEquals("", dom.value)
        assert(!dom.pop())
    }

    @Test
    fun getValue() {
        assertNotNull(Domain.fromString("foo-bar.com"))
        assertNotNull(Domain.fromString("foo-bar.baz.com"))

        // The Domain class is expected to squash case
        assertEquals(Domain.fromString("FOO.bar.com")?.value, "foo.bar.com")

        assertNull(Domain.fromString("a bad-id.com"))
        assertNull(Domain.fromString("also_bad.com"))
    }

    @Test
    fun parent() {
        assertEquals(Domain.fromString("foo-bar.baz.com")?.parent(), "baz.com")
        assertNull(Domain.fromString("baz.com")?.parent())
        assertNull(Domain.fromString("com")?.parent())
    }

    @Test
    fun pop() {
        val dom = Domain.fromString("foo-bar.baz.com")!!
        assertTrue(dom.pop())
        assertEquals(dom.toString(), "baz.com")
        assertTrue(dom.pop())
        assertEquals(dom.toString(), "com")
        assertTrue(dom.pop())
        assertEquals(dom.toString(), "")
        assertFalse(dom.pop())
    }

    @Test
    fun push() {
        var dom = Domain.fromString("baz.com")!!
        assertTrue(dom.push("foo-bar"))
        assertEquals(dom.toString(), "foo-bar.baz.com")

        dom = Domain.fromString("camelot.com")!!
        assertTrue(dom.push("spam.eggs"))
        assertEquals(dom.toString(), "spam.eggs.camelot.com")
    }
}