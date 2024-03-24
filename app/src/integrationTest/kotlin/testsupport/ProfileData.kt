package testsupport

import keznacl.EncryptionPair
import keznacl.SigningPair
import libkeycard.*

// Test profile data for the administrator account used in integration tests
private const val adminKeycard = "Type:User\r\n" +
        "Index:1\r\n" +
        "Name:Administrator\r\n" +
        "User-ID:admin\r\n" +
        "Workspace-ID:ae406c5e-2673-4d3e-af20-91325d9623ca\r\n" +
        "Domain:example.com\r\n" +
        "Contact-Request-Verification-Key:ED25519:E?_z~5@+tkQz!iXK?oV<Zx(ec;=27C8Pjm((kRc|\r\n" +
        "Contact-Request-Encryption-Key:CURVE25519:mO?WWA-k2B2O|Z%fA`~s3^\$iiN{5R->#jxO@cy6{\r\n" +
        "Encryption-Key:CURVE25519:Umbw0Y<^cf1DN|>X38HCZO@Je(zSe6crC6X_C_0F\r\n" +
        "Verification-Key:ED25519:6|HBWrxMY6-?r&Sm)_^PLPerpqOj#b&x#N_#C3}p\r\n" +
        "Time-To-Live:14\r\n" +
        "Expires:2024-02-20\r\n" +
        "Timestamp:2024-01-21T20:02:41Z\r\n"

val ADMIN_PROFILE_DATA = mutableMapOf(
    "name" to "Administrator",
    "uid" to "admin",
    "wid" to "ae406c5e-2673-4d3e-af20-91325d9623ca",
    "domain" to "example.com",
    "address" to "admin/example.com",
    "waddress" to "ae406c5e-2673-4d3e-af20-91325d9623ca/example.com",
    "password" to "Linguini2Pegboard*Album",
    "passhash" to "\$argon2id\$v=19\$m=65536,t=2,p=1\$anXvadxtNJAYa2cUQFqKSQ" +
            "\$zLbLnmbtluKQIOKHk0Hb7+kQZHmZG4Uxf3DI7soKiYE",
    "crencryption.public" to "CURVE25519:mO?WWA-k2B2O|Z%fA`~s3^\$iiN{5R->#jxO@cy6{",
    "crencryption.private" to "CURVE25519:2bLf2vMA?GA2?L~tv<PA9XOw6e}V~ObNi7C&qek>",
    "crsigning.public" to "ED25519:E?_z~5@+tkQz!iXK?oV<Zx(ec;=27C8Pjm((kRc|",
    "crsigning.private" to "ED25519:u4#h6LEwM6Aa+f<++?lma4Iy63^}V\$JOP~ejYkB;",
    "encryption.public" to "CURVE25519:Umbw0Y<^cf1DN|>X38HCZO@Je(zSe6crC6X_C_0F",
    "encryption.private" to "CURVE25519:Bw`F@ITv#sE)2NnngXWm7RQkxg{TYhZQbebcF5b$",
    "signing.public" to "ED25519:6|HBWrxMY6-?r&Sm)_^PLPerpqOj#b&x#N_#C3}p",
    "signing.private" to "ED25519:p;XXU0XF#UO^}vKbC-wS(#5W6=OEIFmR2z`rS1j+",
    "storage" to "XSALSA20:M^z-E(u3QFiM<QikL|7|vC|aUdrWI6VhN+jt>GH}",
    "folder" to "XSALSA20:H)3FOR}+C8(4Jm#\$d+fcOXzK=Z7W+ZVX11jI7qh*",
    "device.public" to "CURVE25519:mO?WWA-k2B2O|Z%fA`~s3^\$iiN{5R->#jxO@cy6{",
    "device.private" to "CURVE25519:2bLf2vMA?GA2?L~tv<PA9XOw6e}V~ObNi7C&qek>",
    "devid" to "3abaa743-40d9-4897-ac77-6a7783083f30",
    "regcode" to "Undamaged Shining Amaretto Improve Scuttle Uptake",
    "reghash" to "\$argon2id\$v=19\$m=1048576,t=10,p=4\$0QufQhLAVhgDqbr//8/hTA\$ocFjWRDrqEhLcedJG95CAt2CKQgkyDak7VMpfjwvveY",
    "keycard" to adminKeycard,

    "name.formatted" to "Mensago Administrator",
    "name.given" to "Mensago",
    "name.family" to "Administrator",
)

internal const val userKeycard = "Type:User\r\n" +
        "Index:1\r\n" +
        "Name:Corbin Simons\r\n" +
        "User-ID:csimons\r\n" +
        "Workspace-ID:4418bf6c-000b-4bb3-8111-316e72030468\r\n" +
        "Domain:example.com\r\n" +
        "Contact-Request-Verification-Key:ED25519:d0-oQb;{QxwnO{=!|^62+E=UYk2Y3mr2?XKScF4D\r\n" +
        "Contact-Request-Encryption-Key:CURVE25519:j(IBzX*F%OZF;g77O8jrVjM1a`Y<6-ehe{S;{gph\r\n" +
        "Encryption-Key:CURVE25519:nSRso=K(WF{P+4x5S*5?Da-rseY-^>S8VN#v+)IN\r\n" +
        "Verification-Key:ED25519:k^GNIJbl3p@N=j8diO-wkNLuLcNF6#JF=@|a}wFE\r\n" +
        "Time-To-Live:14\r\n" +
        "Expires:2024-02-20\r\n" +
        "Timestamp:2024-01-21T20:02:41Z\r\n"

val USER_PROFILE_DATA = mutableMapOf(
    "name" to "Corbin Simons",
    "uid" to "csimons",
    "wid" to "4418bf6c-000b-4bb3-8111-316e72030468",
    "domain" to "example.com",
    "address" to "csimons/example.com",
    "waddress" to "4418bf6c-000b-4bb3-8111-316e72030468/example.com",
    "password" to "MyS3cretPassw*rd",
    "passhash" to "\$argon2id\$v=19\$m=65536,t=2,p=1\$ejzAtaom5H1y6wnLH" +
            "vrb7g\$ArzyFkg5KH5rp8fa6/7iLp/kAVLh9kaSJQfUKMnHWRM",
    "crencryption.public" to "CURVE25519:j(IBzX*F%OZF;g77O8jrVjM1a`Y<6-ehe{S;{gph",
    "crencryption.private" to "CURVE25519:55t6A0y%S?{7c47p(R@C*X#at9Y`q5(Rc#YBS;r}",
    "crsigning.public" to "ED25519:d0-oQb;{QxwnO{=!|^62+E=UYk2Y3mr2?XKScF4D",
    "crsigning.private" to "ED25519:ip52{ps^jH)t\$k-9bc_RzkegpIW?}FFe~BX&<V}9",
    "encryption.public" to "CURVE25519:nSRso=K(WF{P+4x5S*5?Da-rseY-^>S8VN#v+)IN",
    "encryption.private" to "CURVE25519:4A!nTPZSVD#tm78d=-?1OIQ43{ipSpE;@il{lYkg",
    "signing.public" to "ED25519:k^GNIJbl3p@N=j8diO-wkNLuLcNF6#JF=@|a}wFE",
    "signing.private" to "ED25519:;NEoR>t9n3v%RbLJC#*%n4g%oxqzs)&~k+fH4uqi",
    "storage" to "XSALSA20:(bk%y@WBo3&}(UeXeHeHQ|1B}!rqYF20DiDG+9^Q",
    "folder" to "XSALSA20:-DfH*_9^tVtb(z9j3Lu@_(=ow7q~8pq^<;;f%2_B",
    "device.public" to "CURVE25519:94|@e{Kpsu_Qe{L@_U;QnOHz!eJ5zz?V@>+K)6F}",
    "device.private" to "CURVE25519:!x2~_pSSCx1M\$n7{QBQ5e*%~ytBzKL_C(bCviqYh",
    "devid" to "fd21b07b-6112-4a89-b998-a1c55755d9d7",
    "keycard" to userKeycard,

    "name.formatted" to "Corbin Simons",
    "name.given" to "Corbin",
    "name.family" to "Simons",
    "gender" to "Male",
    "website.personal" to "https://www.example.com",
    "website.mensago" to "https://mensago.org",
    "phone.mobile" to "555-555-1234",
    "birthday" to "19750415",
    "anniversary" to "0714",
    "mastodon" to "@corbinsimons@example.com",
    "email.personal" to "corbin.simons@example.com",
)


class TestProfileData(val data: MutableMap<String, Any>) {
    val name: String
        get() {
            return data["name"]!! as String
        }
    val uid: UserID
        get() {
            return data["uid"]!! as UserID
        }
    val wid: RandomID
        get() {
            return data["wid"]!! as RandomID
        }
    val domain: Domain
        get() {
            return data["domain"]!! as Domain
        }
    val address: MAddress
        get() {
            return data["address"]!! as MAddress
        }
    val waddress: WAddress
        get() {
            return data["waddress"]!! as WAddress
        }
    val password: String
        get() {
            return data["password"]!! as String
        }
    val passhash: String
        get() {
            return data["passhash"]!! as String
        }
    val crsigning: SigningPair
        get() {
            return data["crsigning"]!! as SigningPair
        }
    val crencryption: EncryptionPair
        get() {
            return data["crencryption"]!! as EncryptionPair
        }
    val signing: SigningPair
        get() {
            return data["signing"]!! as SigningPair
        }
    val encryption: EncryptionPair
        get() {
            return data["encryption"]!! as EncryptionPair
        }
    val devid: RandomID
        get() {
            return data["devid"]!! as RandomID
        }
    val devpair: EncryptionPair
        get() {
            return data["devpair"]!! as EncryptionPair
        }
    val keycard: Keycard
        get() {
            return data["keycard"]!! as Keycard
        }
}

val gAdminProfileData = TestProfileData(
    mutableMapOf(
        "name" to "Administrator",
        "uid" to UserID.fromString("admin")!!,
        "wid" to RandomID.fromString("ae406c5e-2673-4d3e-af20-91325d9623ca")!!,
        "domain" to Domain.fromString("example.com")!!,
        "address" to MAddress.fromString("admin/example.com")!!,
        "waddress" to WAddress.fromString("ae406c5e-2673-4d3e-af20-91325d9623ca/example.com")!!,
        "password" to "Linguini2Pegboard*Album",
        "passhash" to "\$argon2id\$v=19\$m=65536,t=2,p=1\$anXvadxtNJAYa2cUQFqKSQ" +
                "\$zLbLnmbtluKQIOKHk0Hb7+kQZHmZG4Uxf3DI7soKiYE",

        "crsigning" to SigningPair.fromStrings(
            "ED25519:E?_z~5@+tkQz!iXK?oV<Zx(ec;=27C8Pjm((kRc|",
            "ED25519:u4#h6LEwM6Aa+f<++?lma4Iy63^}V\$JOP~ejYkB;",
        ).getOrThrow(),
        "crencryption" to EncryptionPair.fromStrings(
            "CURVE25519:mO?WWA-k2B2O|Z%fA`~s3^\$iiN{5R->#jxO@cy6{",
            "CURVE25519:2bLf2vMA?GA2?L~tv<PA9XOw6e}V~ObNi7C&qek>"
        ).getOrThrow(),
        "signing" to SigningPair.fromStrings(
            "ED25519:6|HBWrxMY6-?r&Sm)_^PLPerpqOj#b&x#N_#C3}p",
            "ED25519:p;XXU0XF#UO^}vKbC-wS(#5W6=OEIFmR2z`rS1j+"
        ).getOrThrow(),
        "encryption" to EncryptionPair.fromStrings(
            "CURVE25519:Umbw0Y<^cf1DN|>X38HCZO@Je(zSe6crC6X_C_0F",
            "CURVE25519:Bw`F@ITv#sE)2NnngXWm7RQkxg{TYhZQbebcF5b$"
        ).getOrThrow(),

        "devid" to RandomID.fromString("3abaa743-40d9-4897-ac77-6a7783083f30")!!,
        "devpair" to EncryptionPair.fromStrings(
            "CURVE25519:mO?WWA-k2B2O|Z%fA`~s3^\$iiN{5R->#jxO@cy6{",
            "CURVE25519:2bLf2vMA?GA2?L~tv<PA9XOw6e}V~ObNi7C&qek>",
        ),
        "keycard" to run {
            val card = Keycard.new("User")!!
            card.entries.add(UserEntry.fromString(adminKeycard).getOrThrow())
            card
        },
    )
)

val gUserProfileData = TestProfileData(
    mutableMapOf(
        "name" to "Corbin Simons",
        "uid" to UserID.fromString("csimons")!!,
        "wid" to RandomID.fromString("4418bf6c-000b-4bb3-8111-316e72030468")!!,
        "domain" to Domain.fromString("example.com")!!,
        "address" to MAddress.fromString("csimons/example.com")!!,
        "waddress" to WAddress.fromString("4418bf6c-000b-4bb3-8111-316e72030468/example.com")!!,
        "password" to "MyS3cretPassw*rd",
        "passhash" to "\$argon2id\$v=19\$m=65536,t=2,p=1\$ejzAtaom5H1y6wnLH" +
                "vrb7g\$ArzyFkg5KH5rp8fa6/7iLp/kAVLh9kaSJQfUKMnHWRM",

        "crsigning" to SigningPair.fromStrings(
            "ED25519:d0-oQb;{QxwnO{=!|^62+E=UYk2Y3mr2?XKScF4D",
            "ED25519:ip52{ps^jH)t\$k-9bc_RzkegpIW?}FFe~BX&<V}9",
        ).getOrThrow(),
        "crencryption" to EncryptionPair.fromStrings(
            "CURVE25519:j(IBzX*F%OZF;g77O8jrVjM1a`Y<6-ehe{S;{gph",
            "CURVE25519:55t6A0y%S?{7c47p(R@C*X#at9Y`q5(Rc#YBS;r}"
        ).getOrThrow(),
        "signing" to SigningPair.fromStrings(
            "ED25519:k^GNIJbl3p@N=j8diO-wkNLuLcNF6#JF=@|a}wFE",
            "ED25519:;NEoR>t9n3v%RbLJC#*%n4g%oxqzs)&~k+fH4uqi"
        ).getOrThrow(),
        "encryption" to EncryptionPair.fromStrings(
            "CURVE25519:nSRso=K(WF{P+4x5S*5?Da-rseY-^>S8VN#v+)IN",
            "CURVE25519:4A!nTPZSVD#tm78d=-?1OIQ43{ipSpE;@il{lYkg"
        ).getOrThrow(),

        "devid" to RandomID.fromString("fd21b07b-6112-4a89-b998-a1c55755d9d7")!!,
        "devpair" to EncryptionPair.fromStrings(
            "CURVE25519:94|@e{Kpsu_Qe{L@_U;QnOHz!eJ5zz?V@>+K)6F}",
            "CURVE25519:!x2~_pSSCx1M\$n7{QBQ5e*%~ytBzKL_C(bCviqYh"
        ).getOrThrow(),
        "keycard" to run {
            val card = Keycard.new("User")!!
            card.entries.add(UserEntry.fromString(userKeycard).getOrThrow())
            card
        },
    )
)
