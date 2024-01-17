package libkeycard

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import keznacl.CryptoString
import keznacl.SigningPair
import keznacl.getPreferredHashAlgorithm

class KeycardTest {

    @Test
    fun basicTesting() {
        val cardData = "----- BEGIN ENTRY -----\r\n" +
                "Type:Organization\r\n" +
                "Index:1\r\n" +
                "Name:Example, Inc.\r\n" +
                "Domain:example.com\r\n" +
                "Contact-Admin:c590b44c-798d-4055-8d72-725a7942f3f6/example.com\r\n" +
                "Language:en\r\n" +
                "Primary-Verification-Key:ED25519:r#r*RiXIN-0n)BzP3bv`LA&t4LFEQNF0Q@\$N~RF*\r\n" +
                "Encryption-Key:CURVE25519:SNhj2K`hgBd8>G>lW$!pXiM7S-B!Fbd9jT2&{{Az\r\n" +
                "Time-To-Live:14\r\n" +
                "Expires:2023-08-18\r\n" +
                "Timestamp:2022-08-18T17:26:40Z\r\n" +
                "Hash:BLAKE3-256:ocU4XayQkNEHh-zHevRuX;YJmKp4AD2eo_R|9I31\r\n" +
                "Organization-Signature:ED25519:Rlusb?3WRvd95Hc<aYat\$GH2AszxNVvF8Hly&eYyqys0on&vx=tCAKbe~!owEi5HQnTafpEdoJ*F&`TZ\r\n" +
                "----- END ENTRY -----\r\n" +
                "----- BEGIN ENTRY -----\r\n" +
                "Type:Organization\r\n" +
                "Index:2\r\n" +
                "Name:Example, Inc.\r\n" +
                "Domain:example.com\r\n" +
                "Contact-Admin:c590b44c-798d-4055-8d72-725a7942f3f6/example.com\r\n" +
                "Language:en\r\n" +
                "Primary-Verification-Key:ED25519:f!7Asqr9w7v=fsX@<?_s*}Btn>WfrgOZk?M)YOGr\r\n" +
                "Secondary-Verification-Key:ED25519:r#r*RiXIN-0n)BzP3bv`LA&t4LFEQNF0Q@\$N~RF*\r\n" +
                "Encryption-Key:CURVE25519:Yoj)=FNDj>sc0U^JCypwu=W1~c!C`1^xlul{|GT`\r\n" +
                "Time-To-Live:14\r\n" +
                "Expires:2023-08-18\r\n" +
                "Timestamp:2022-08-18T17:26:40Z\r\n" +
                "Custody-Signature:ED25519:N603IF=MJ-Se<!g+%3rx{mUlOp7}XqIwE<SGEhG~R;@(1gzM|V7lcXw++%NPGuS2zS@yRLpSxmc0oW-I\r\n" +
                "Previous-Hash:BLAKE3-256:ocU4XayQkNEHh-zHevRuX;YJmKp4AD2eo_R|9I31\r\n" +
                "Hash:BLAKE3-256:vg65eVmF~r#^zG*gwF2XIEl3*l;J>aB*iLGkN?m6\r\n" +
                "Organization-Signature:ED25519:^O)N7oeF9Af)7fS{Kde_3hPcne{CLfmm3f{%w1`08xp9Df_v9Fc~zCe<k~-\$_yzNA<I3*5&J_0<UlNE5\r\n" +
                "----- END ENTRY -----\r\n"

        // Test basic entry parsing. Note that no validation of entry data is performed with this
        // call
        val card = Keycard.fromString(cardData).getOrThrow()
        assertEquals(2, card.entries.size)

        // findByHash()
        val foundCard = card.findByHash(CryptoString.fromString(
            "BLAKE3-256:vg65eVmF~r#^zG*gwF2XIEl3*l;J>aB*iLGkN?m6")!!)
        assertNotNull(foundCard)
        assertNull(card.findByHash(CryptoString.fromString("FAKE:aaaaaaa")!!))

        // getOwner()
        assertEquals("example.com", card.getOwner()!!)
    }


    @Test
    fun orgChainVerify() {
        val (firstEntry, firstKeys) = makeCompliantOrgEntry().getOrThrow()

        val primarySPair = SigningPair.from(firstKeys["primary.public"]!!,
            firstKeys["primary.private"]!!).getOrThrow()

        val card = Keycard.new("Organization")!!
        card.entries.add(firstEntry)

        card.chain(primarySPair).getOrThrow()
        assert(card.verify().getOrThrow())
    }

    @Test
    fun userChainVerify() {
        val (firstEntry, firstKeys) = makeCompliantUserEntry().getOrThrow()

        val crSPair = SigningPair.from(firstKeys["crsigning.public"]!!,
            firstKeys["crsigning.private"]!!).getOrThrow()

        val card = Keycard.new("User")!!
        card.entries.add(firstEntry)

        val newKeys = card.chain(crSPair).getOrThrow()

        // Unlike organizational cards, user cards are cross-signed, so when chain() returns the
        // card isn't complete.

        val orgSPair = SigningPair.from(firstKeys["orgsigning.public"]!!,
            firstKeys["orgsigning.private"]!!).getOrThrow()
        card.crossSign(orgSPair).let { if (it != null) throw it }

        val newCRSPair = SigningPair.from(newKeys["crsigning.public"]!!,
            newKeys["crsigning.private"]!!).getOrThrow()
        card.userSign(getPreferredHashAlgorithm(), newCRSPair).let { if (it != null) throw it }

        assert(card.verify().getOrThrow())
    }
}