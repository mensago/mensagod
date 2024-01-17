package libkeycard

import keznacl.SigningPair
import keznacl.VerificationKey
import org.junit.jupiter.api.Test

class EntryFieldTest {

    @Test
    fun fromStringsTest1() {

        // Type

        assert(EntryField.fromStrings("Type", "broken").exceptionOrNull()
                is BadFieldValueException)
        val typeField = EntryField.fromStrings("Type", "Organization")
            .getOrThrow()
        assert(typeField is StringField)
        assert(typeField.toString() == "Organization")

        // Index

        listOf("0", "broken").forEach {
            assert(EntryField.fromStrings("Index", it).exceptionOrNull()
                    is BadFieldValueException)
        }
        val indexField = EntryField.fromStrings("Index", "12").getOrThrow()
        assert(indexField is IntegerField)
        assert(indexField.toString() == "12")

        // Name

        listOf(" ", " Corbin Simons").forEach {
            assert(EntryField.fromStrings("Name", it).exceptionOrNull()
                    is BadFieldValueException)
        }
        val nameField = EntryField.fromStrings("Name", "Corbin Simons")
            .getOrThrow()
        assert(nameField is StringField)
        assert(nameField.toString() == "Corbin Simons")

        // User-ID

        listOf("has spaces", "consecutive..dots", "bad#symbols", " needs trimmed ",
            "영일이삼사오육칠팔구").forEach {
            assert(EntryField.fromStrings("User-ID", it).exceptionOrNull()
                    is BadFieldValueException)
        }
        val uidField = EntryField.fromStrings("User-ID", "cats4life")
            .getOrThrow()
        assert(uidField is StringField)
        assert(uidField.toString() == "cats4life")

        // Local-ID

        listOf("has spaces", "consecutive..dots", "bad#symbols", " needs trimmed ").forEach {
            assert(EntryField.fromStrings("User-ID", it).exceptionOrNull()
                    is BadFieldValueException)
        }
        val luidField = EntryField.fromStrings("Local-ID", "영일이삼사오육칠팔구")
            .getOrThrow()
        assert(luidField is StringField)
        assert(luidField.toString() == "영일이삼사오육칠팔구")
    }

    @Test
    fun fromStringsTest2() {

        // Workspace-ID

        listOf(" ", "cats4life"," 11111111-aaaa-bbbb-4444-555555555555 ").forEach {
            assert(EntryField.fromStrings("Workspace-ID", it).exceptionOrNull()
                    is BadFieldValueException)
        }
        val widField = EntryField.fromStrings("Workspace-ID",
            "11111111-aaaa-bbbb-4444-555555555555").getOrThrow()
        assert(widField is StringField)
        assert(widField.toString() == "11111111-aaaa-bbbb-4444-555555555555")

        // Domain

        listOf(" ", "cats4life..com"," a.b.c.div ").forEach {
            assert(EntryField.fromStrings("Domain", it).exceptionOrNull()
                    is BadFieldValueException)
        }
        val domField = EntryField.fromStrings("Domain",
            "a.b.c.div").getOrThrow()
        assert(domField is StringField)
        assert(domField.toString() == "a.b.c.div")

        // Contact Fields

        listOf("Contact-Admin", "Contact-Support", "Contact-Abuse").forEach { fieldName ->
            listOf(" ", "admin/a.b.c.div").forEach {
                assert(EntryField.fromStrings(fieldName, it).exceptionOrNull()
                        is BadFieldValueException)
            }
            val contactField = EntryField.fromStrings(fieldName,
                "11111111-aaaa-bbbb-4444-555555555555/a.b.c.div").getOrThrow()
            assert(contactField is WAddressField)
            assert(contactField.toString() == "11111111-aaaa-bbbb-4444-555555555555/a.b.c.div")
        }

        // Verification key fields

        val signingPair = SigningPair.fromStrings("ED25519:)8id(gE02^S<{3H>9B;X4{DuYcb`%wo^mC&1lN88",
            "ED25519:msvXw(nII<Qm6oBHc+92xwRI3>VFF-RcZ=7DEu3|").getOrThrow()
        val signature = signingPair.sign("aaaaaaaa".toByteArray()).getOrThrow()

        listOf("Primary-Verification-Key", "Secondary-Verification-Key", "Contact-Request-Verification-Key")
            .forEach { fieldName ->

                listOf(" ", " ED25519:)8id(gE02^S<{3H>9B;X4{DuYcb`%wo^mC&1lN88 ").forEach {
                    assert(EntryField.fromStrings(fieldName, it).exceptionOrNull()
                            is BadFieldValueException)
                }
                val vkeyField = EntryField.fromStrings(fieldName,
                    "ED25519:)8id(gE02^S<{3H>9B;X4{DuYcb`%wo^mC&1lN88").getOrThrow()
                assert(vkeyField is CryptoStringField)
                assert(vkeyField.toString() == "ED25519:)8id(gE02^S<{3H>9B;X4{DuYcb`%wo^mC&1lN88")

                val vkey = VerificationKey.from((vkeyField as CryptoStringField).value).getOrThrow()
                assert(vkey.verify("aaaaaaaa".toByteArray(), signature).getOrThrow())
            }

        // Encryption key fields

        // Because we've already tested usage in the previous case, we don't need to do much for these
        listOf("Encryption-Key", "Contact-Request-Encryption-Key").forEach { fieldName ->

            val ekeyField = EntryField.fromStrings(fieldName,
                "CURVE25519:@b?cjpeY;<&y+LSOA&yUQ&ZIrp(JGt{W\$*V>ATLG").getOrThrow()
            assert(ekeyField is CryptoStringField)
            assert(ekeyField.toString() == "CURVE25519:@b?cjpeY;<&y+LSOA&yUQ&ZIrp(JGt{W\$*V>ATLG")
        }
    }

    @Test
    fun fromStringsTest3() {

        // Language

        listOf(" ", " es "," en,es ").forEach {
            assert(EntryField.fromStrings("Language", it).exceptionOrNull()
                    is BadFieldValueException)
        }
        val langField = EntryField.fromStrings("Language", "fr,de").getOrThrow()
        assert(langField is StringField)
        assert(langField.toString() == "fr,de")

        // Time-to-Live

        listOf("broken", " 2 ").forEach {
            assert(EntryField.fromStrings("Time-To-Live", it).exceptionOrNull()
                    is BadFieldValueException)
        }
        val indexField = EntryField.fromStrings("Time-To-Live", "12").getOrThrow()
        assert(indexField is IntegerField)
        assert(indexField.toString() == "12")

        // Expires

        listOf(" ", " 2026-01-13T13:30:48Z ").forEach {
            assert(EntryField.fromStrings("Expires", it).exceptionOrNull()
                    is BadFieldValueException)
        }
        val expireField = EntryField.fromStrings("Expires", "2023-06-01")
            .getOrThrow()
        assert(expireField is DatestampField)
        assert(expireField.toString() == "2023-06-01")

        // Timestamp

        listOf(" ", " 2026-01-13T13:30:48Z ").forEach {
            assert(EntryField.fromStrings("Timestamp", it).exceptionOrNull()
                    is BadFieldValueException)
        }
        val timeField = EntryField.fromStrings("Timestamp", "2026-01-13T13:30:48Z")
            .getOrThrow()
        assert(timeField is TimestampField)
        assert(timeField.toString() == "2026-01-13T13:30:48Z")
    }
}