package mensagod

import keznacl.EncryptionPair
import keznacl.SigningPair
import libkeycard.Keycard
import libkeycard.OrgEntry
import libkeycard.RandomID
import org.apache.commons.io.FileUtils
import java.io.File
import java.nio.file.Paths
import java.sql.Connection

//! This file contains setup functions needed by the integration tests

// THESE KEYS ARE STORED ON GITLAB! DO NOT USE THESE FOR ANYTHING EXCEPT TESTS!!

// Test Organization Information

// Name: Example.com
// Contact-Admin: ae406c5e-2673-4d3e-af20-91325d9623ca/acme.com
// Support and Abuse accounts are forwarded to Admin
// Language: en

// Initial Organization Primary Signing Key: {UNQmjYhz<(-ikOBYoEQpXPt<irxUF*nq25PoW=_
// Initial Organization Primary Verification Key: r#r*RiXIN-0n)BzP3bv`LA&t4LFEQNF0Q@$N~RF*
// Initial Organization Primary Verification Key Hash:
// BLAKE2B-256:ag29av@TUvh-V5KaB2l}H=m?|w`}dvkS1S1&{cMo

// Initial Organization Encryption Key: SNhj2K`hgBd8>G>lW$!pXiM7S-B!Fbd9jT2&{{Az
// Initial Organization Encryption Key Hash: BLAKE2B-256:-Zz4O7J;m#-rB)2llQ*xTHjtblwm&kruUVa_v(&W
// Initial Organization Decryption Key: WSHgOhi+bg=<bO^4UoJGF-z9`+TBN{ds?7RZ;w3o

// THESE KEYS ARE STORED ON GITLAB! DO NOT USE THESE FOR ANYTHING EXCEPT TESTS!!

// Test profile data for the administrator account used in integration tests
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

    "name.formatted" to "Mensago Administrator",
    "name.given" to "Mensago",
    "name.family" to "Administrator",
)

/** Returns the canonical version of the path specified. */
fun getPathForTest(testName: String): String? {
    return try {
        Paths.get("build", "testfiles", testName).toAbsolutePath().toString()
    } catch (e: Exception) { null }
}

/** Creates a new test folder for file-based tests and returns the top-level path created. */
fun makeTestFolder(name: String): String {
    val dir = File(getPathForTest(name)!!)
    if (dir.exists())
        FileUtils.cleanDirectory(dir)
    else
        dir.mkdirs()

    return dir.toString()
}

fun setupTest(config: ServerConfig): Connection {
    return resetDB(config)
}

/**
 * Adds basic data to the database as if setup had been run. It also rotates the org keycard so that
 * there are two entries. Returns data needed for tests, such as the keys
 */
fun initServer(db: Connection): Map<String, String> {
    val initialOSPair = SigningPair.fromStrings(
        "ED25519:r#r*RiXIN-0n)BzP3bv`LA&t4LFEQNF0Q@\$N~RF*",
        "ED25519:{UNQmjYhz<(-ikOBYoEQpXPt<irxUF*nq25PoW=_"
    ).getOrThrow()
    val initialOEPair = EncryptionPair.fromStrings(
        "CURVE25519:SNhj2K`hgBd8>G>lW\$!pXiM7S-B!Fbd9jT2&{{Az",
        "CURVE25519:WSHgOhi+bg=<bO^4UoJGF-z9`+TBN{ds?7RZ;w3o"
    ).getOrThrow()

    val rootEntry = OrgEntry()
    rootEntry.setFieldInteger("Index", 1)
    rootEntry.setField("Name", "Example, Inc.")
    rootEntry.setField("Contact-Admin",
        "c590b44c-798d-4055-8d72-725a7942f3f6/example.com")
    rootEntry.setField("Language", "en")
    rootEntry.setField("Domain", "example.com")
    rootEntry.setField("Primary-Verification-Key", initialOSPair.publicKey.toString())
    rootEntry.setField("Encryption-Key", initialOEPair.publicKey.toString())

    rootEntry.isDataCompliant()?.let { throw it }
    rootEntry.hash()?.let { throw it }
    rootEntry.sign("Organization-Signature", initialOSPair)?.let { throw it }
    rootEntry.verifySignature("Organization-Signature", initialOSPair).getOrThrow()
    rootEntry.isCompliant()?.let { throw it }

    val orgCard = Keycard.new("Organization")!!
    orgCard.entries.add(rootEntry)

    var stmt = db.prepareStatement("""INSERT INTO keycards(owner,creationtime,index,entry,fingerprint)
        VALUES('organization',?,?,?,?);""")
    stmt.setString(1, rootEntry.getFieldString("Timestamp")!!)
    stmt.setInt(2, rootEntry.getFieldInteger("Index")!!)
    stmt.setString(3, rootEntry.getFullText(null).getOrThrow())
    stmt.setString(4, rootEntry.getAuthString("Hash")!!.toString())
    stmt.execute()

    stmt = db.prepareStatement("""INSERT INTO orgkeys(creationtime,pubkey,privkey,purpose,fingerprint)
        VALUES(?,?,?,'encrypt',?);""")
    stmt.setString(1, rootEntry.getFieldString("Timestamp")!!)
    stmt.setString(2, initialOEPair.publicKey.toString())
    stmt.setString(3, initialOEPair.privateKey.toString())
    stmt.setString(4, initialOEPair.publicKey.calcHash().getOrThrow().toString())
    stmt.execute()

    stmt = db.prepareStatement("""INSERT INTO orgkeys(creationtime,pubkey,privkey,purpose,fingerprint)
        VALUES(?,?,?,'sign',?);""")
    stmt.setString(1, rootEntry.getFieldString("Timestamp")!!)
    stmt.setString(2, initialOSPair.publicKey.toString())
    stmt.setString(3, initialOSPair.privateKey.toString())
    stmt.setString(4, initialOSPair.publicKey.calcHash().getOrThrow().toString())
    stmt.execute()

    // Now that we've added the organization's root keycard entry and keys, chain a new entry and
    // add it to the database.
    val keys = orgCard.chain(initialOSPair, 365).getOrThrow()

    val newEntry = orgCard.entries[1]

    stmt = db.prepareStatement("""INSERT INTO keycards(owner,creationtime,index,entry,fingerprint)
        VALUES('organization',?,?,?,?);""")
    stmt.setString(1, newEntry.getFieldString("Timestamp")!!)
    stmt.setInt(2, newEntry.getFieldInteger("Index")!!)
    stmt.setString(3, newEntry.getFullText(null).getOrThrow())
    stmt.setString(4, newEntry.getAuthString("Hash")!!.toString())
    stmt.execute()

    stmt = db.prepareStatement("""UPDATE orgkeys SET creationtime=?,pubkey=?,privkey=?,fingerprint=?
        WHERE purpose='encrypt';""")
    stmt.setString(1, newEntry.getFieldString("Timestamp")!!)
    stmt.setString(2, keys["encryption.public"].toString())
    stmt.setString(3, keys["encryption.private"].toString())
    stmt.setString(4, keys["encryption.public"]!!.calcHash().getOrThrow().toString())
    stmt.execute()

    stmt = db.prepareStatement("""UPDATE orgkeys SET creationtime=?,pubkey=?,privkey=?,fingerprint=?
        WHERE purpose='sign';""")
    stmt.setString(1, newEntry.getFieldString("Timestamp")!!)
    stmt.setString(2, keys["primary.public"].toString())
    stmt.setString(3, keys["primary.private"].toString())
    stmt.setString(4, keys["primary.public"]!!.calcHash().getOrThrow().toString())
    stmt.execute()

    stmt = db.prepareStatement("""INSERT INTO orgkeys(creationtime,pubkey,privkey,purpose,fingerprint)
        VALUES(?,?,?,'altsign',?);""")
    stmt.setString(1, rootEntry.getFieldString("Timestamp")!!)
    stmt.setString(2, initialOSPair.publicKey.toString())
    stmt.setString(3, initialOSPair.privateKey.toString())
    stmt.setString(4, initialOSPair.publicKey.calcHash().getOrThrow().toString())
    stmt.execute()

    // Preregister the admin account

    val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"]!!)!!
    val regCode = "Undamaged Shining Amaretto Improve Scuttle Uptake"
    stmt = db.prepareStatement("""INSERT INTO prereg(wid,uid,domain,regcode) 
        VALUES(?,'admin','example.com',?);""")
    stmt.setString(1, adminWID.toString())
    stmt.setString(2, regCode)
    stmt.execute()

    // Set up abuse/support forwarding to admin

    val abuseWID = RandomID.fromString("f8cfdbdf-62fe-4275-b490-736f5fdc82e3")!!
    stmt = db.prepareStatement("""INSERT INTO workspaces(wid,uid,domain,password,passtype,status,wtype) 
        VALUES(?,'abuse','example.com','-', '','active','alias');""")
    stmt.setString(1, abuseWID.toString())
    stmt.execute()

    stmt = db.prepareStatement("""INSERT INTO aliases(wid,alias) VALUES(?,?)""")
    stmt.setString(1, abuseWID.toString())
    stmt.setString(2, ADMIN_PROFILE_DATA["waddress"]!!)
    stmt.execute()

    val supportWID = RandomID.fromString("f0309ef1-a155-4655-836f-55173cc1bc3b")!!
    stmt = db.prepareStatement("""INSERT INTO workspaces(wid,uid,domain,password,passtype,status,wtype) 
        VALUES(?,'support','example.com','-', '','active','alias');""")
    stmt.setString(1, supportWID.toString())
    stmt.execute()

    stmt = db.prepareStatement("""INSERT INTO aliases(wid,alias) VALUES(?,?)""")
    stmt.setString(1, supportWID.toString())
    stmt.setString(2, ADMIN_PROFILE_DATA["waddress"]!!)
    stmt.execute()

    return mutableMapOf(
        "ovkey" to keys["primary.public"].toString(),
        "oskey" to keys["primary.private"].toString(),
        "oekey" to keys["encryption.public"].toString(),
        "odkey" to keys["encryption.private"].toString(),
        "admin_wid" to adminWID.toString(),
        "admin_regcode" to regCode,
        "abuse_wid" to abuseWID.toString(),
        "support_wid" to supportWID.toString(),
    )
}