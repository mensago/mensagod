package libmensago

import keznacl.CryptoString
import libkeycard.*
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class SchemaTest {
    private val devID = RandomID.fromString("3ec47ff7-2147-4599-a309-fbec8b9bc9d3")!!
    private val devKey = CryptoString
        .fromString("CURVE25519:mO?WWA-k2B2O|Z%fA`~s3^\$iiN{5R->#jxO@cy6{")!!
    private val domain = Domain.fromString("example.com")!!
    private val userID = UserID.fromString("csimons")!!
    private val testPath = MServerPath("/ wsp a909b468-c7d6-4ab2-93a3-d56fab981a10")
    private val unixTime = 1709000000L

    @Test
    fun basicTest() {
        val schema = Schema(
            MsgField("Device-ID", MsgFieldType.RandomID, true),
            MsgField("Device-Key", MsgFieldType.CryptoString, true),
            MsgField("Password-Algorithm", MsgFieldType.String, true),
            MsgField("Domain", MsgFieldType.Domain, true),

            MsgField("User-ID", MsgFieldType.UserID, false),
            MsgField("Destination", MsgFieldType.Path, false),
            MsgField("Time", MsgFieldType.UnixTime, false),
            MsgField("Index", MsgFieldType.Integer, false),
        )

        // Test Case #1: Success
        schema.validate(
            mapOf(
                "Device-ID" to devID.toString(),
                "Device-Key" to devKey.toString(),
                "Password-Algorithm" to "cleartext",
                "Domain" to domain.toString(),
            )
        ) { name, e -> throw Exception("$e: $name") }

        // Test Case #2: Invalid optional
        schema.validate(
            mapOf(
                "Device-ID" to devID.toString(),
                "Device-Key" to devKey.toString(),
                "Password-Algorithm" to "cleartext",
                "Domain" to domain.toString(),
                "Time" to "foobar",
            )
        ) { name, e ->
            assertEquals("Time", name)
            assert(e is BadFieldValueException)
        }


        // Test Case #2: Required field missing
        schema.validate(
            mapOf(
                "Device-ID" to devID.toString(),
                "Device-Key" to devKey.toString(),
                "Password-Algorithm" to "cleartext",
            )
        ) { name, e ->
            assertEquals("Domain", name)
            assert(e is MissingFieldException)
        }
    }

    @Test
    fun validatorTest() {
        val schema = Schema(
            MsgField("Device-Key", MsgFieldType.CryptoString, false),
            MsgField("Domain", MsgFieldType.Domain, false),
            MsgField("Index", MsgFieldType.Integer, false),
            MsgField("Destination", MsgFieldType.Path, false),
            MsgField("Device-ID", MsgFieldType.RandomID, false),
            MsgField("Password-Algorithm", MsgFieldType.String, false),
            MsgField("Time", MsgFieldType.UnixTime, false),
            MsgField("User-ID", MsgFieldType.UserID, false),
        )

        assertNull(schema.getCryptoString("Device-Key", mapOf("Device-Key" to "bad data")))
        assertNull(schema.getDomain("Domain", mapOf("Domain" to "bad data")))
        assertNull(schema.getInteger("Index", mapOf("Index" to "bad data")))
        assertNull(schema.getPath("Destination", mapOf("Destination" to "bad data")))
        assertNull(schema.getInteger("Device-ID", mapOf("Index" to "bad data")))
        assertNull(schema.getString("Password-Algorithm", mapOf("Password-Algorithm" to "")))
        assertNull(schema.getUnixTime("Time", mapOf("Time" to "bad data")))
        assertNull(schema.getUserID("User-ID", mapOf("User-ID" to "bad data")))

        val goodData = mapOf(
            "Device-Key" to devKey.toString(),
            "Domain" to domain.toString(),
            "Index" to "10",
            "Destination" to testPath.toString(),
            "Device-ID" to devID.toString(),
            "Password-Algorithm" to "cleartext",
            "Time" to unixTime.toString(),
            "User-ID" to userID.toString(),
        )

        assertEquals(devKey, schema.getCryptoString("Device-Key", goodData))
        assertEquals(domain, schema.getDomain("Domain", goodData))
        assertEquals(10, schema.getInteger("Index", goodData))
        assertEquals(testPath, schema.getPath("Destination", goodData))
        assertEquals(devID, schema.getRandomID("Device-ID", goodData))
        assertEquals("cleartext", schema.getString("Password-Algorithm", goodData))
        assertEquals(unixTime, schema.getUnixTime("Time", goodData))
        assertEquals(userID, schema.getUserID("User-ID", goodData))
    }
}
