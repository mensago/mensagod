package keznacl

import kotlin.test.Test
import kotlin.test.assertEquals

class PasswordTest {

    @Test
    fun basicTest() {
        assert(getSupportedPasswordAlgorithms().contains("ARGON2ID"))
        assertEquals("ARGON2ID", getPreferredPasswordAlgorithm())
    }
}