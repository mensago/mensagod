package libkeycard

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class UserIDTest {

    @Test
    fun getValue() {

        // -- Tests for valid user IDs

        // Basic ASCII and other Unicode
        val uids = listOf("cavsfan4life",
            "valid_e-mail.123",
            "Valid.but.needs_case-squashed",
            "GoodID",
            "alsogoooood",
            "11111111-1111-1111-1111-111111111111",
        )
        uids.forEach { assertNotNull(UserID.fromString(it)) }

        // -- Test cases to invalidate non-compliant user IDs

        // Invalid because dots are not allowed to be consecutive
        assertNull(UserID.fromString("invalid..number1"))

        // Symbols are also not allowed
        assertNull(UserID.fromString("invalid#2"))

        // Nor is internal whitespace
        assertNull(UserID.fromString("invalid number 3"))

        // -- Special test cases

        assertEquals("valid.but.needs_case-squashed",
            UserID.fromString("Valid.but.needs_case-squashed").toString())

        assertEquals(UserID.fromString("type_test_ID")!!.type, IDType.UserID)

        assertEquals(
            UserID.fromString("11111111-1111-1111-1111-111111111111")!!.type,
                IDType.WorkspaceID
        )

        val wid = RandomID.fromString("11111111-1111-1111-1111-111111111111")!!
        val fromWID = UserID.fromWID(wid)
        assertEquals(IDType.WorkspaceID, fromWID.type)
    }
}