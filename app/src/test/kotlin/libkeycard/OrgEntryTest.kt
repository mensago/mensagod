package libkeycard

import keznacl.BadValueException
import keznacl.SigningPair
import org.junit.jupiter.api.Test
import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlin.test.assertEquals
import kotlin.test.assertNull

class OrgEntryTest {

    @Test
    fun entryFieldMethods() {

        val entry = OrgEntry()

        assert(entry.hasField("Index"))
        val indexField = entry.getField("Index")
        assert(indexField is IntegerField)
        assert((indexField as IntegerField).value == 1)

        entry.setField("Name", "Corbin Simons")
        assert(entry.hasField("Name"))
        assertEquals("Corbin Simons", entry.getFieldString("Name"))
        assertNull(entry.getFieldInteger("Corbin Simons"))
        entry.deleteField("Name")
        entry.deleteField("Name")

        entry.setFieldInteger("Index", 2)
        assertEquals(2, entry.getFieldInteger("Index"))
    }

    @Test
    fun entryExpiration() {

        val entry = OrgEntry()

        val now = Instant.now()
        var expires = entry.getField("Expires")!! as DatestampField
        assert(now.isBefore(expires.value.value))
        entry.setExpires(1)

        expires = entry.getField("Expires")!! as DatestampField
        now.plus(3, ChronoUnit.DAYS).isAfter(expires.value.value)
    }

    @Test
    fun entryCopy() {

        val cardData =
            "Type:Organization\r\n" +
                    "Index:2\r\n" +
                    "Name:Acme + Inc.\r\n" +
                    "Domain:example.com\r\n" +
                    "Contact-Admin:11111111-2222-2222-2222-333333333333/acme.com\r\n" +
                    "Contact-Support:11111111-2222-2222-2222-444444444444/acme.com\r\n" +
                    "Contact-Abuse:11111111-2222-2222-2222-555555555555/acme.com\r\n" +
                    "Language:en\r\n" +
                    "Primary-Verification-Key:ED25519:)8id(gE02^S<{3H>9B;X4{DuYcb`%wo^mC&1lN88\r\n" +
                    "Secondary-Verification-Key:ED25519:^j&t+&+q3fgPe1%PLmW4i|RCV|KNWZBLByIUZg+~\r\n" +
                    "Encryption-Key:CURVE25519:@b?cjpeY;<&y+LSOA&yUQ&ZIrp(JGt{W$*V>ATLG\r\n" +
                    "Time-To-Live:14\r\n" +
                    "Expires:2023-12-31\r\n" +
                    "Timestamp:2022-05-01T13:52:11Z\r\n" +
                    "Custody-Signature:ED25519:x3)dYq@S0rd1Rfbie*J7kF{fkxQ=J=A)OoO1WGx97o-utWtfbw\r\n" +
                    "Previous-Hash:BLAKE2B-256:tSl@QzD1w-vNq@CC-5`(\$KuxO0#aOl^-cy(l7XXT\r\n" +
                    "Hash:BLAKE2B-256:6XG#bSNuJyLCIJxUa-O`V~xR{kF4UWxaFJvPvcwg\r\n" +
                    "Organization-Signature:ED25519:x3)dYq@S0rd1Rfbie*J7kF{fkxQ=J=A)OoO1WGx97o-utWtfbw\r\n"

        val entry = OrgEntry.fromString(cardData).getOrThrow()
        val copiedEntry = entry.copy().getOrThrow()

        val expectedFields = listOf("Index", "Name", "Domain", "Contact-Admin", "Contact-Support",
            "Contact-Abuse", "Language", "Time-To-Live", "Expires", "Timestamp")
        expectedFields.forEach {
            if (!copiedEntry.hasField(it))
                throw BadFieldException(it)
        }
    }

    @Test
    fun orgEntryBasic() {

        val entry = OrgEntry()
        assertNull(entry.getOwner())
        entry.setField("Domain", "example.com")
        assert(entry.getOwner()!! == "example.com")
    }

    @Test
    fun orgEntryDataCompliant() {

        // NOTE: This card data is data compliant only -- the signatures are just throwaways and
        // this data will not pass a full compliance check
        val cardData =
            "Type:Organization\r\n" +
            "Index:2\r\n" +
            "Name:Acme + Inc.\r\n" +
            "Domain:example.com\r\n" +
            "Contact-Admin:11111111-2222-2222-2222-333333333333/acme.com\r\n" +
            "Contact-Support:11111111-2222-2222-2222-444444444444/acme.com\r\n" +
            "Contact-Abuse:11111111-2222-2222-2222-555555555555/acme.com\r\n" +
            "Language:en\r\n" +
            "Primary-Verification-Key:ED25519:)8id(gE02^S<{3H>9B;X4{DuYcb`%wo^mC&1lN88\r\n" +
            "Secondary-Verification-Key:ED25519:^j&t+&+q3fgPe1%PLmW4i|RCV|KNWZBLByIUZg+~\r\n" +
            "Encryption-Key:CURVE25519:@b?cjpeY;<&y+LSOA&yUQ&ZIrp(JGt{W$*V>ATLG\r\n" +
            "Time-To-Live:14\r\n" +
            "Expires:2023-12-31\r\n" +
            "Timestamp:2022-05-01T13:52:11Z\r\n" +
            "Custody-Signature:ED25519:x3)dYq@S0rd1Rfbie*J7kF{fkxQ=J=A)OoO1WGx97o-utWtfbw\r\n" +
            "Previous-Hash:BLAKE2B-256:tSl@QzD1w-vNq@CC-5`(\$KuxO0#aOl^-cy(l7XXT\r\n" +
            "Hash:BLAKE2B-256:6XG#bSNuJyLCIJxUa-O`V~xR{kF4UWxaFJvPvcwg\r\n" +
            "Organization-Signature:ED25519:x3)dYq@S0rd1Rfbie*J7kF{fkxQ=J=A)OoO1WGx97o-utWtfbw\r\n"

        val entry = OrgEntry.fromString(cardData).getOrThrow()
        val error = entry.isDataCompliant()
        if (error != null) throw error
    }

    @Test
    fun orgEntryGetText() {
        val (entry, keys) = makeCompliantOrgEntry().getOrThrow()
        val entryText = entry.getText()

        val expectedText =
            "Type:Organization\r\n" +
            "Index:1\r\n" +
            "Name:Example, Inc.\r\n" +
            "Domain:example.com\r\n" +
            "Contact-Admin:11111111-2222-2222-2222-333333333333/example.com\r\n" +
            "Contact-Abuse:11111111-2222-2222-2222-555555555555/example.com\r\n" +
            "Contact-Support:11111111-2222-2222-2222-444444444444/example.com\r\n" +
            "Language:en\r\n" +
            "Primary-Verification-Key:${keys["primary.public"]}\r\n" +
            "Secondary-Verification-Key:${keys["secondary.public"]}\r\n" +
            "Encryption-Key:${keys["encryption.public"]}\r\n" +
            "Time-To-Live:14\r\n" +
            "Expires:2025-06-01\r\n" +
            "Timestamp:2022-05-20T12:00:00Z\r\n"

        assertEquals(expectedText.length, entryText.length)
        if (entryText != expectedText) {
            val pairs = expectedText.zip(entryText)
            val inequalIndex = pairs.indexOfFirst { it.first != it.second }
            println(pairs.take(inequalIndex).map { it.first }.joinToString(""))
            print("Difference: expected '${pairs[inequalIndex].first}', " +
                    "got: '${pairs[inequalIndex].second}'")
            throw BadValueException()
        }
    }

    @Test
    fun orgEntryGetFullText() {
        val (entry, keys) = makeCompliantOrgEntry().getOrThrow()

        val baseText =
            "Type:Organization\r\n" +
                    "Index:1\r\n" +
                    "Name:Example, Inc.\r\n" +
                    "Domain:example.com\r\n" +
                    "Contact-Admin:11111111-2222-2222-2222-333333333333/example.com\r\n" +
                    "Contact-Abuse:11111111-2222-2222-2222-555555555555/example.com\r\n" +
                    "Contact-Support:11111111-2222-2222-2222-444444444444/example.com\r\n" +
                    "Language:en\r\n" +
                    "Primary-Verification-Key:${keys["primary.public"]}\r\n" +
                    "Secondary-Verification-Key:${keys["secondary.public"]}\r\n" +
                    "Encryption-Key:${keys["encryption.public"]}\r\n" +
                    "Time-To-Live:14\r\n" +
                    "Expires:2025-06-01\r\n" +
                    "Timestamp:2022-05-20T12:00:00Z\r\n"

        // Start with testing the Hash level
        var actualText = entry.getFullText("Organization-Signature").getOrThrow()
        var expectedText = baseText + "Hash:" +
                getExpectedOrgEntryAuthString("Hash") + "\r\n"
        if (expectedText != actualText) {
            println("Full text mismatch at Hash level in orgEntryGetFullText:\n")
            println("Expected Text: '''$expectedText'''\n" +
                    "Text Received: '''$actualText'''\n")
            throw BadFieldValueException(null)
        }

        actualText = entry.getFullText(null).getOrThrow()
        expectedText = baseText +
                "Hash:" + getExpectedOrgEntryAuthString("Hash") + "\r\n" +
                "Organization-Signature:" +
                    getExpectedOrgEntryAuthString("Organization-Signature") + "\r\n"
        if (expectedText != actualText) {
            println("Full text mismatch at full text level in orgEntryGetFullText:\n")
            println("Expected Text: '''$expectedText'''\n" +
                    "Text Received: '''$actualText'''\n")
            throw BadFieldValueException(null)
        }
    }

    // A test for isCompliant() isn't necessary as calls to makeCompliantOrgEntry() in other
    // tests ensure that this is also covered.

    @Test
    fun orgEntryHashSignVerify() {
        val (entry, keys) = makeCompliantOrgEntry().getOrThrow()

        // Because makeCompliantOrgEntry() hashes and signs the entry it generates, we just
        // need to check the hash. The value compared to below is a hash generated by a Python
        // script known to work correctly which operates on the test card stored in src/testfiles.

        val expectedHash = getExpectedOrgEntryAuthString("Hash")!!
        val actualHash = entry.getAuthString("Hash")!!
        if (expectedHash.toString() != actualHash.toString()) {
            println("Org hash mismatch in orgEntryHashSignVerify:\n")
            println("Org keycard: '''${entry.getText()}'''\n")
            println("Expected Hash: $expectedHash\n" +
                    "Hash Received: $actualHash")
            throw BadFieldValueException(null)
        }

        val expectedSig = getExpectedOrgEntryAuthString("Organization-Signature")!!
        val actualSig = entry.getAuthString("Organization-Signature")!!
        if (expectedSig.toString() != actualSig.toString()) {
            println("Org signature mismatch in orgEntryHashSignVerify:\n")
            println("Org keycard: '''${entry.getText()}'''\n")
            println("Expected Sig: $expectedSig\n" +
                    "Sig Received: $actualSig\n")
            throw BadFieldValueException(null)
        }

        val primarySPair = SigningPair.from(keys["primary.public"]!!, keys["primary.private"]!!)
                                .getOrThrow()
        assert(entry.verifySignature("Organization-Signature", primarySPair).getOrThrow())
    }

    @Test
    fun orgEntryChainVerify() {
        val (firstEntry, firstKeys) = makeCompliantOrgEntry().getOrThrow()

        val primarySPair = SigningPair.from(firstKeys["primary.public"]!!,
                firstKeys["primary.private"]!!).getOrThrow()

        val (newEntry) = firstEntry.chain(primarySPair).getOrThrow()
        assert(newEntry.verifyChain(firstEntry).getOrThrow())
    }

    @Test
    fun orgEntryRevoke() {
        val (firstEntry, firstKeys) = makeCompliantOrgEntry().getOrThrow()

        val primarySPair = SigningPair.from(firstKeys["primary.public"]!!,
            firstKeys["primary.private"]!!).getOrThrow()

        val card = Keycard.new("Organization")!!
        card.entries.add(firstEntry)

        // The keys we receive from chaining don't matter -- they will be revoked
        card.chain(primarySPair).getOrThrow()
        assert(card.verify().getOrThrow())

        val (newRoot) = card.entries.last().revoke().getOrThrow()
        newRoot.isCompliant().let { if (it != null) throw it }
    }
}