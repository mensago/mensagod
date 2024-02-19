package libkeycard

import keznacl.CryptoString
import keznacl.EncryptionPair
import keznacl.SigningPair

// These methods are setup calls for many of the tests. Because they are so rigorous, they end up
// being full-on tests in their own right.

/**
 * This function creates a fully-compliant root org entry.
 *
 * NOTE: If any of this data is changed, you will need to update the corresponding auth strings
 * provided by getExpectedOrgEntryAuthString in order for all the unit tests to pass.
 */
fun makeCompliantOrgEntry(): Result<Pair<Entry, Map<String, CryptoString>>> {

    // Start off by making the requisite keypairs

    val primarySPair = SigningPair.fromStrings(
        "ED25519:)8id(gE02^S<{3H>9B;X4{DuYcb`%wo^mC&1lN88",
        "ED25519:msvXw(nII<Qm6oBHc+92xwRI3>VFF-RcZ=7DEu3|").getOrThrow()
    val secondarySPair = SigningPair.fromStrings(
        "ED25519:^j&t+&+q3fgPe1%PLmW4i|RCV|KNWZBLByIUZg+~",
        "ED25519:4%Xb|FD_^#62(<)y0>C7LM0K=bdq7pwV62{V&O+1").getOrThrow()
    val ePair = EncryptionPair.fromStrings(
        "CURVE25519:@b?cjpeY;<&y+LSOA&yUQ&ZIrp(JGt{W$*V>ATLG",
        "CURVE25519:nQxAR1Rh{F4gKR<KZz)*)7}5s_^!`!eb!sod0<aT").getOrThrow()

    val outMap = mapOf(
        "primary.public" to primarySPair.publicKey,
        "primary.private" to primarySPair.privateKey,
        "secondary.public" to secondarySPair.publicKey,
        "secondary.private" to secondarySPair.privateKey,
        "encryption.public" to ePair.publicKey,
        "encryption.private" to ePair. privateKey
    )

    val cardData =
        "Type:Organization\r\n" +
        "Index:1\r\n" +
        "Name:Example, Inc.\r\n" +
        "Domain:example.com\r\n" +
        "Contact-Admin:11111111-2222-2222-2222-333333333333/example.com\r\n" +
        "Contact-Support:11111111-2222-2222-2222-444444444444/example.com\r\n" +
        "Contact-Abuse:11111111-2222-2222-2222-555555555555/example.com\r\n" +
        "Language:en\r\n" +
        "Primary-Verification-Key:${primarySPair.publicKey}\r\n" +
        "Secondary-Verification-Key:${secondarySPair.publicKey}\r\n" +
        "Encryption-Key:${ePair.publicKey}\r\n" +
        "Time-To-Live:14\r\n" +
        "Expires:2025-06-01\r\n" +
        "Timestamp:2022-05-20T12:00:00Z\r\n"
    val outEntry = OrgEntry.fromString(cardData).getOrThrow()

    outEntry.hash("BLAKE2B-256").let { if (it != null) throw it }
    outEntry.sign("Organization-Signature", primarySPair).let { if (it != null) throw it }
    val valid = outEntry.verifySignature("Organization-Signature", primarySPair).getOrThrow()
    if (!valid) throw ComplianceFailureException()

    return Result.success(Pair(outEntry, outMap))
}

/**
 * This test function provides the expected values for the hash and organizational signature. This
 * is to ensure that the cryptography is applied correctly. These values are provided by another
 * implementation to ensure compatibility.
 *
 * NOTE: these values will need updated if any of the test data in makeCompliantOrgEntry() is
 * altered so that all the unit tests pass.
 */
fun getExpectedOrgEntryAuthString(authStrName: String): CryptoString? {
    return when (authStrName) {
        "Hash" -> CryptoString.fromString(
            "BLAKE2B-256:I@Okw1%n#^HfvL?BQ6KT8Iw(3Mvr*x6ZV4I67#@N")
        "Organization-Signature" -> CryptoString.fromString(
        "ED25519:Q>~a^e^#HG6eRvOPMo^84Uy0~<O(p1k5@@BLyZ{`*Q04x+PG0!xd`yA4j*a*EIEYmW_^YE8WF_>Q+%fj")
        else -> null
    }
}

fun makeCompliantUserEntry(): Result<Pair<Entry, Map<String, CryptoString>>> {

    val orgSPair = SigningPair.fromStrings(
        "ED25519:)8id(gE02^S<{3H>9B;X4{DuYcb`%wo^mC&1lN88",
        "ED25519:msvXw(nII<Qm6oBHc+92xwRI3>VFF-RcZ=7DEu3|").getOrThrow()

    val crSPair = SigningPair.fromStrings(
        "ED25519:d0-oQb;{QxwnO{=!|^62+E=UYk2Y3mr2?XKScF4D",
        "ED25519:ip52{ps^jH)t\$k-9bc_RzkegpIW?}FFe~BX&<V}9").getOrThrow()
    val crEPair = EncryptionPair.fromStrings(
        "CURVE25519:j(IBzX*F%OZF;g77O8jrVjM1a`Y<6-ehe{S;{gph",
        "CURVE25519:55t6A0y%S?{7c47p(R@C*X#at9Y`q5(Rc#YBS;r}").getOrThrow()
    val sPair = SigningPair.fromStrings(
        "ED25519:6|HBWrxMY6-?r&Sm)_^PLPerpqOj#b&x#N_#C3}p",
        "ED25519:p;XXU0XF#UO^}vKbC-wS(#5W6=OEIFmR2z`rS1j+").getOrThrow()
    val ePair = EncryptionPair.fromStrings(
        "CURVE25519:nSRso=K(WF{P+4x5S*5?Da-rseY-^>S8VN#v+)IN",
        "CURVE25519:4A!nTPZSVD#tm78d=-?1OIQ43{ipSpE;@il{lYkg").getOrThrow()

    val outMap = mapOf(
        "orgsigning.public" to orgSPair.publicKey,
        "orgsigning.private" to orgSPair.privateKey,

        "crsigning.public" to crSPair.publicKey,
        "crsigning.private" to crSPair.privateKey,
        "crencryption.public" to crEPair.publicKey,
        "crencryption.private" to crEPair.privateKey,
        "signing.public" to sPair.publicKey,
        "signing.private" to sPair.privateKey,
        "encryption.public" to ePair.publicKey,
        "encryption.private" to ePair. privateKey
    )

    val cardData =
        "Index:1\r\n" +
        "Name:Corbin Simons\r\n" +
        "Workspace-ID:4418bf6c-000b-4bb3-8111-316e72030468\r\n" +
        "User-ID:csimons\r\n" +
        "Domain:example.com\r\n" +
        "Contact-Request-Verification-Key:${crSPair.publicKey}\r\n" +
        "Contact-Request-Encryption-Key:${crEPair.publicKey}\r\n" +
        "Verification-Key:${sPair.publicKey}\r\n" +
        "Encryption-Key:${ePair.publicKey}\r\n" +
        "Time-To-Live:14\r\n" +
        "Expires:2025-06-01\r\n" +
        "Timestamp:2022-05-20T12:00:00Z\r\n"

    val outEntry = UserEntry.fromString(cardData).getOrThrow()

    // We have finished creating a root entry for a user. Now we need to generate the
    // signatures: Organization, Previous-Hash (always required for user entries), Hash, and
    // then finally the user signature.

    outEntry.sign("Organization-Signature", orgSPair).let { if (it != null) throw it }
    outEntry.addAuthString("Previous-Hash",
        getExpectedUserEntryAuthString("Previous-Hash")!!)
    outEntry.hash("BLAKE2B-256").let { if (it != null) throw it }
    outEntry.sign("User-Signature", crSPair).let { if (it != null) throw it }

    if (!outEntry.verifySignature("Organization-Signature", orgSPair).getOrThrow())
        throw ComplianceFailureException("Org signature failed to verify")
    if (!outEntry.verifySignature("User-Signature", crSPair).getOrThrow())
        throw ComplianceFailureException("User signature failed to verify")

    return Result.success(Pair(outEntry, outMap))
}

/**
 * This test function provides the expected values for the hashes and signatures. This
 * is to ensure that the cryptography is applied correctly. These values are provided by another
 * implementation to ensure compatibility.
 *
 * NOTE: these values will need updated if any of the test data in makeCompliantUserEntry() is
 * altered so that all the unit tests pass.
 */
fun getExpectedUserEntryAuthString(authStrName: String): CryptoString? {
    return when (authStrName) {
        "Organization-Signature" -> CryptoString.fromString(
            "ED25519:!_K*oL|W&QA01O*mqvX4x-@ML06(}(GiV&1fDx*2sxntw^HEkdm?}=%eVt-FX2<Tk6yHV;@7lwF8CZf0")
        "Previous-Hash" -> CryptoString.fromString(
            "BLAKE2B-256:I@Okw1%n#^HfvL?BQ6KT8Iw(3Mvr*x6ZV4I67#@N")
        "Hash" -> CryptoString.fromString(
            "BLAKE2B-256:#sCz<;m8yX_hrtjwNjEmxF?i=t=OFr;(G{-U2ZEY")
        "User-Signature" -> CryptoString.fromString(
            "ED25519:Wyi9K()e_EzWNfSNyva>&;urqbG791U&I}YYu+AS6~)eULy+MdFn_RqxFRi#9%}bID}5>ceNn<28*Eht")
        else -> null
    }
}
