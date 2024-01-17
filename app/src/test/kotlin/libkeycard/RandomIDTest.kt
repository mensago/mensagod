package libkeycard

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class RandomIDTest {

    @Test
    fun randomIDTests() {
        assertNotNull(RandomID.fromString("5a56260b-aa5c-4013-9217-a78f094432c3"))

        val wid = RandomID.generate()
        assertNotNull(RandomID.fromString(wid.value))

        assertNotNull(RandomID.fromUserID(UserID.fromString("5a56260b-aa5c-4013-9217-a78f094432c3")!!))
        assertNull(RandomID.fromUserID(UserID.fromString("cats4life")!!))
    }
}