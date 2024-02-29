package libmensago.resolver

import libkeycard.Entry
import libkeycard.Keycard
import libkeycard.OrgEntry
import libkeycard.UserEntry
import libmensago.EntrySubject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class KeycardCacheTest {

    @Test
    fun basicTest() {
        var entry: Entry = OrgEntry()
        entry.setField("Domain", "example.com")?.let { throw it }
        val org1 = Keycard.new("Organization")!!
        org1.entries.add(entry)
        val orgSub1 = EntrySubject.fromEntry(entry)!!

        entry = OrgEntry()
        entry.setField("Domain", "example.net")?.let { throw it }
        val org2 = Keycard.new("Organization")!!
        org2.entries.add(entry)

        entry = UserEntry()
        with(entry) {
            setField("Workspace-ID", "8a26608e-a304-4495-ab75-149e55bcdd69")
                ?.let { throw it }
            setField("User-ID", "csimons")
                ?.let { throw it }
            setField("Domain", "example.com")?.let { throw it }
        }
        val user1 = Keycard.new("User")!!
        user1.entries.add(entry)

        entry = UserEntry()
        with(entry) {
            setField("Workspace-ID", "fe0eb0b9-3d1e-46aa-8b9e-015421f3cf10")
                ?.let { throw it }
            setField("User-ID", "rbrannan")
                ?.let { throw it }
            setField("Domain", "example.com")?.let { throw it }
        }
        val user2 = Keycard.new("User")!!
        user2.entries.add(entry)

        val cache = KeycardCache(3)
        assertNull(cache.get(orgSub1))
        assertEquals("", cache.debugState())
        cache.put(org1)
        assertEquals("example.com", cache.debugState())
        cache.put(user1)
        assertEquals("example.com\ncsimons/example.com", cache.debugState())
        cache.put(org2)
        cache.put(user2)
        assertEquals(
            "csimons/example.com\nexample.net\nrbrannan/example.com",
            cache.debugState()
        )
    }

}