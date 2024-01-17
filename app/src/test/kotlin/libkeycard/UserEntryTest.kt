package libkeycard

import keznacl.BadValueException
import keznacl.SigningPair
import keznacl.VerificationKey
import keznacl.getPreferredHashAlgorithm
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

// TODO: Update UserEntryTest to include support for the Local-User-ID field

class UserEntryTest {

    @Test
    fun userEntryBasic() {

        val entry = UserEntry()
        assertNull(entry.getOwner())
        entry.setField("Domain", "example.com")
        assertNull(entry.getOwner())
        entry.setField("Workspace-ID", "11111111-2222-2222-2222-333333333333")
        entry.setField("User-ID", "cats4life")
        assert(entry.getOwner()!! == "11111111-2222-2222-2222-333333333333/example.com")
    }

    @Test
    fun userEntryDataCompliant() {

        // NOTE: This card data is data compliant only -- the signatures are just throwaways and
        // this data will not pass a full compliance check
        val cardData =
            "Type:User\r\n" +
            "Index:1\r\n" +
            "Name:Corbin Simons\r\n" +
            "User-ID:csimons\r\n" +
            "Workspace-ID:4418bf6c-000b-4bb3-8111-316e72030468\r\n" +
            "Domain:example.com\r\n" +
            "Contact-Request-Verification-Key:ED25519:d0-oQb;{QxwnO{=!|^62+E=UYk2Y3mr2?XKScF4D\r\n" +
            "Contact-Request-Encryption-Key:CURVE25519:j(IBzX*F%OZF;g77O8jrVjM1a`Y<6-ehe{S;{gph\r\n" +
            "Encryption-Key:CURVE25519:nSRso=K(WF{P+4x5S*5?Da-rseY-^>S8VN#v+)IN\r\n" +
            "Verification-Key:ED25519:6|HBWrxMY6-?r&Sm)_^PLPerpqOj#b&x#N_#C3}p\r\n" +
            "Time-To-Live:14\r\n" +
            "Expires:2025-06-01\r\n" +
            "Timestamp:2022-05-20T12:00:00Z\r\n" +
            "Organization-Signature:ED25519:%WEh<1SA;@68mf1j!W>6>JL7Uf0PMiZIsMFRnQFBuZZ1" +
                "?i^}$^elxZ<<*>N8As@(9#eM-I|DA>0KQT!T\r\n" +
            "Previous-Hash:BLAKE2B-256:5p?~_i\$tLp<u5)cide0_jfVkSEw9tuaXOQK<jx1X\r\n" +
            "Hash:BLAKE2B-256:m@b+Gq}GZqRD@M?<D7y)?v`W#12rxX&sQ-Fc-(|6\r\n" +
            "User-Signature:ED25519:%MBaz#oQ>Mge+0X<+S0OLGW8*`{k&%W=LB^*kLN2HB`N5d@nqJWo" +
                "xk+rys0@1rR8`Cj)Y`ZcWX^>G+`v\r\n"

        val entry = UserEntry.fromString(cardData).getOrThrow()
        val error = entry.isDataCompliant()
        if (error != null) throw error
    }

    @Test
    fun userEntryGetText() {
        val (entry, keys) = makeCompliantUserEntry().getOrThrow()
        val entryText = entry.getText()

        val expectedText =
            "Type:User\r\n" +
            "Index:1\r\n" +
            "Name:Corbin Simons\r\n" +
            "User-ID:csimons\r\n" +
            "Workspace-ID:4418bf6c-000b-4bb3-8111-316e72030468\r\n" +
            "Domain:example.com\r\n" +
            "Contact-Request-Verification-Key:${keys["crsigning.public"]}\r\n" +
            "Contact-Request-Encryption-Key:${keys["crencryption.public"]}\r\n" +
            "Encryption-Key:${keys["encryption.public"]}\r\n" +
            "Verification-Key:${keys["signing.public"]}\r\n" +
            "Time-To-Live:14\r\n" +
            "Expires:2025-06-01\r\n" +
            "Timestamp:2022-05-20T12:00:00Z\r\n"

        if (expectedText.length != entryText.length) {
            println("Expected text:\n'''$expectedText'''\n")
            println("Received text:\n'''$entryText'''\n")
            throw BadValueException()
        }
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
    fun userEntryGetFullText() {
        val (entry) = makeCompliantUserEntry().getOrThrow()

        val baseText =
            "Type:User\r\n" +
            "Index:1\r\n" +
            "Name:Corbin Simons\r\n" +
            "User-ID:csimons\r\n" +
            "Workspace-ID:4418bf6c-000b-4bb3-8111-316e72030468\r\n" +
            "Domain:example.com\r\n" +
            "Contact-Request-Verification-Key:ED25519:d0-oQb;{QxwnO{=!|^62+E=UYk2Y3mr2?XKScF4D\r\n" +
            "Contact-Request-Encryption-Key:CURVE25519:j(IBzX*F%OZF;g77O8jrVjM1a`Y<6-ehe{S;{gph\r\n" +
            "Encryption-Key:CURVE25519:nSRso=K(WF{P+4x5S*5?Da-rseY-^>S8VN#v+)IN\r\n" +
            "Verification-Key:ED25519:6|HBWrxMY6-?r&Sm)_^PLPerpqOj#b&x#N_#C3}p\r\n" +
            "Time-To-Live:14\r\n" +
            "Expires:2025-06-01\r\n" +
            "Timestamp:2022-05-20T12:00:00Z\r\n"

        // Start with testing the Previous-Hash level
        var actualText = entry.getFullText("Previous-Hash").getOrThrow()
        var expectedText = baseText +
                "Organization-Signature:" +
                    getExpectedUserEntryAuthString("Organization-Signature") + "\r\n"
        if (expectedText != actualText) {
            println("Full text mismatch at Previous-Hash level in userEntryGetFullText:\n")
            println("Expected Text: '''$expectedText'''\n" +
                    "Text Received: '''$actualText'''\n")
            throw BadFieldValueException(null)
        }

        actualText = entry.getFullText("Hash").getOrThrow()
        expectedText = baseText +
                "Organization-Signature:" +
                getExpectedUserEntryAuthString("Organization-Signature") + "\r\n" +
                "Previous-Hash:" +
                getExpectedUserEntryAuthString("Previous-Hash") + "\r\n"
        if (expectedText != actualText) {
            println("Full text mismatch at Hash level in userEntryGetFullText:\n")
            println("Expected Text: '''$expectedText'''\n" +
                    "Text Received: '''$actualText'''\n")
            throw BadFieldValueException(null)
        }

        actualText = entry.getFullText("User-Signature").getOrThrow()
        expectedText = baseText +
                "Organization-Signature:" +
                getExpectedUserEntryAuthString("Organization-Signature") + "\r\n" +
                "Previous-Hash:" +
                getExpectedUserEntryAuthString("Previous-Hash") + "\r\n" +
                "Hash:" + getExpectedUserEntryAuthString("Hash") + "\r\n"
        if (expectedText != actualText) {
            println("Full text mismatch at User-Signature level in userEntryGetFullText:\n")
            println("Expected Text: '''$expectedText'''\n" +
                    "Text Received: '''$actualText'''\n")
            throw BadFieldValueException(null)
        }

        actualText = entry.getFullText(null).getOrThrow()
        expectedText = baseText +
                "Organization-Signature:" +
                    getExpectedUserEntryAuthString("Organization-Signature") + "\r\n" +
                "Previous-Hash:" +
                    getExpectedUserEntryAuthString("Previous-Hash") + "\r\n" +
                "Hash:" + getExpectedUserEntryAuthString("Hash") + "\r\n" +
                "User-Signature:" +
                    getExpectedUserEntryAuthString("User-Signature") + "\r\n"
        if (expectedText != actualText) {
            println("Full text mismatch at full text level in userEntryGetFullText:\n")
            println("Expected Text: '''$expectedText'''\n" +
                    "Text Received: '''$actualText'''\n")
            throw BadFieldValueException(null)
        }
    }

    // A test for isCompliant() isn't necessary as calls to makeCompliantUserEntry() in other
    // tests ensure that this is also covered.

    @Test
    fun userEntryHashSignVerify() {
        val (entry, keys) = makeCompliantUserEntry().getOrThrow()

        // Because makeCompliantUserEntry() hashes and signs the entry it generates, we just
        // need to check the hash. The value compared to below is a hash generated by a Python
        // script known to work correctly which operates on the test card stored in src/testfiles.

        fun testAuthString(authField: String, authName: String) {
            val expectedStr = getExpectedUserEntryAuthString(authField)!!
            val actualStr = entry.getAuthString(authField)!!
            if (expectedStr.toString() != actualStr.toString()) {
                println("$authName mismatch in userEntryHashSignVerify:\n")
                println("User keycard: '''${entry.getText()}'''\n")
                println("Expected $authName: $expectedStr\n" +
                        "$authName Received: $actualStr")
                throw BadFieldValueException(null)
            }
        }

        testAuthString("Organization-Signature", "Org signature")
        testAuthString("Hash", "User Hash")
        testAuthString("User-Signature", "User signature")

        val orgVKey = VerificationKey.from(keys["orgsigning.public"]!!).getOrThrow()
        assert(entry.verifySignature("Organization-Signature", orgVKey).getOrThrow())

        val userVKey = VerificationKey.from(keys["crsigning.public"]!!).getOrThrow()
        assert(entry.verifySignature("User-Signature", userVKey).getOrThrow())
    }

    @Test
    fun userEntryChainVerify() {
        val (firstEntry, firstKeys) = makeCompliantUserEntry().getOrThrow()

        val crSPair = SigningPair.from(firstKeys["crsigning.public"]!!,
            firstKeys["crsigning.private"]!!).getOrThrow()
        val (newEntry) = firstEntry.chain(crSPair).getOrThrow()
        assert(newEntry.verifyChain(firstEntry).getOrThrow())
    }

    @Test
    fun userEntryRevoke() {
        val (firstEntry, firstKeys) = makeCompliantUserEntry().getOrThrow()

        val crSPair = SigningPair.from(firstKeys["crsigning.public"]!!,
            firstKeys["crsigning.private"]!!).getOrThrow()

        // This is the entry and corresponding key set which will be revoked further down
        val (revokedEntry, revokedKeys) = firstEntry.chain(crSPair).getOrThrow()

        val card = Keycard.new("User")!!
        card.entries.add(firstEntry)
        card.entries.add(revokedEntry)

        val orgSPair = SigningPair.from(firstKeys["orgsigning.public"]!!,
            firstKeys["orgsigning.private"]!!).getOrThrow()
        card.crossSign(orgSPair).let { if (it != null) throw it }

        val revokedCRSPair = SigningPair.from(revokedKeys["crsigning.public"]!!,
            revokedKeys["crsigning.private"]!!).getOrThrow()

        card.userSign(getPreferredHashAlgorithm(), revokedCRSPair).let {
            if (it != null) throw it
        }
        assert(card.verify().getOrThrow())

        // Now that we have a completely compliant user keycard, revoke the last entry and start
        // a new one.
        val (newRootEntry, newRootKeys) = card.entries.last().revoke().getOrThrow()

        assertEquals(card.entries.last().getFieldInteger("Index")!!,
            newRootEntry.getFieldInteger("Index")!!-1)

        // Technically we don't *have* to create a new keycard, but it makes the final signature
        // stuff more convenient.
        val newCard = Keycard.new("User")!!
        newCard.entries.add(newRootEntry)
        newCard.crossSign(orgSPair).let { if (it != null) throw it }

        val newCRSPair = SigningPair.from(newRootKeys["crsigning.public"]!!,
            newRootKeys["crsigning.private"]!!).getOrThrow()

        newCard.userSign(getPreferredHashAlgorithm(), newCRSPair).let {
            if (it != null) throw it
        }
        assert(newCard.verify().getOrThrow())
    }

    @Test
    fun branchChainVerify() {
        val (orgEntry) = makeCompliantOrgEntry().getOrThrow()

        // This call makes a completely signed and hashed card from data that already ties it to
        // the org entry created by the corresponding org-specific call. All we have to do is just
        // verify the chain, because both setup functions make entries that pass an isCompliant()
        // call.
        val (userEntry) = makeCompliantUserEntry().getOrThrow()
        assert(userEntry.verifyChain(orgEntry).getOrThrow())
    }
}
