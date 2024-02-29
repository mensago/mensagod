package libmensago.resolver

import libkeycard.OrgEntry
import libkeycard.UserEntry
import libmensago.EntrySubject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class EntryCacheTest {

    @Test
    fun basicTest() {
        val org1 = OrgEntry()
        org1.setField("Domain", "example.com")?.let { throw it }
        val orgSub1 = EntrySubject.fromEntry(org1)!!

        val org2 = OrgEntry()
        org2.setField("Domain", "example.net")?.let { throw it }

        val user1 = UserEntry()
        with(user1) {
            setField("Workspace-ID", "8a26608e-a304-4495-ab75-149e55bcdd69")
                ?.let { throw it }
            setField("User-ID", "csimons")
                ?.let { throw it }
            setField("Domain", "example.com")?.let { throw it }
        }

        val user2 = UserEntry()
        with(user2) {
            setField("Workspace-ID", "fe0eb0b9-3d1e-46aa-8b9e-015421f3cf10")
                ?.let { throw it }
            setField("User-ID", "rbrannan")
                ?.let { throw it }
            setField("Domain", "example.com")?.let { throw it }
        }

        val cache = EntryCache(3)
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