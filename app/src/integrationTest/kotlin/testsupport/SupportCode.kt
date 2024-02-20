package testsupport

import keznacl.Argon2idPassword
import keznacl.CryptoString
import keznacl.EncryptionPair
import keznacl.SigningPair
import libkeycard.*
import libmensago.MServerPath
import libmensago.ResourceNotFoundException
import libmensago.ServerResponse
import mensagod.*
import mensagod.commands.DeviceStatus
import mensagod.dbcmds.*
import org.apache.commons.io.FileUtils
import java.io.File
import java.net.ProtocolException
import java.nio.file.Paths
import java.security.SecureRandom
import java.sql.Connection
import java.time.Instant
import java.util.*

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
        "Timestamp:2024-01-21T20:02:41Z\r\n" +
        "Organization-Signature:ED25519:oC9NsUC-PNW\$G9N^7fZZknug=@KF(u>k4aj8W;=47{jxnrbGPki>YbG65!32y6@jX)Fq>*Uks<ZF-_(H\r\n" +
        "Previous-Hash:BLAKE2B-256:p*{~#L}xycY{Ge3!vY))g&<!{^;Ef\$zd8s@)(Cb6\r\n" +
        "Hash:BLAKE2B-256:aOXSB=4*;RdV;e)^39NR;`9L}^dFxN9rpW)hzNb!\r\n" +
        "User-Signature:ED25519:Ge+1#zpzg|<Dj;p?<BTkARlq~&3ngMFc4?cWbqR-Y){b?h@1+4`b@B#^J-P!B)0E103}=-=oeoRKDNpY\r\n"

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

    "name.formatted" to "Mensago Administrator",
    "name.given" to "Mensago",
    "name.family" to "Administrator",
    "keycard" to adminKeycard,
    "keycard.fingerprint" to "BLAKE2B-256:`-l^-<lxieg9Or0o|8sAl4owSwG(_^yN3TNc5%o(",
)

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

/** Returns the canonical version of the path specified. */
fun getPathForTest(testName: String): String? {
    return try {
        Paths.get("build", "testfiles", testName).toAbsolutePath().toString()
    } catch (e: Exception) { null }
}

/** Creates a new test folder for file-based tests and returns the top-level path created. */
fun makeTestFolder(name: String): String {

    val testdirStr = getPathForTest(name)!!
    val topdirStr = Paths.get(testdirStr,"topdir").toString()
    val topdir = File(testdirStr)
    if (topdir.exists())
        FileUtils.cleanDirectory(topdir)
    else
        topdir.mkdirs()
    File(topdirStr).mkdirs()

    LocalFS.initialize(topdir.toString())?.let { throw it }

    return topdir.toString()
}

/**
 * Adds basic data to the database as if setup had been run. It also rotates the org keycard so that
 * there are two entries. Returns data needed for tests, such as the keys
 */
fun initDB(db: Connection): Map<String, String> {
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
    stmt = db.prepareStatement("""INSERT INTO prereg(wid,uid,domain,regcode) 
        VALUES(?,'admin','example.com',?);""")
    stmt.setString(1, adminWID.toString())
    stmt.setString(2, ADMIN_PROFILE_DATA["reghash"]!!)
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
        "admin_regcode" to ADMIN_PROFILE_DATA["regcode"]!!,
        "abuse_wid" to abuseWID.toString(),
        "support_wid" to supportWID.toString(),
    )
}

/** Test setup command to preregister a user */
fun preregUser(db: DBConn, uid: String? = null, regcode: String? = null, reghash: String? = null,
               wid: String? = null): Map<String,String> {

    val rcode = regcode ?: gRegCodeGenerator.getPassphrase(
        ServerConfig.get().getInteger("security.diceware_wordcount")!!)
    val rhash = reghash ?: Argon2idPassword().updateHash(rcode).getOrThrow()

    val outWID = RandomID.fromString(wid) ?: RandomID.generate()
    val outUID = UserID.fromString(uid)
    preregWorkspace(db, outWID, outUID, gServerDomain, rhash)
    LocalFS.get().entry(MServerPath("/ wsp $outWID")).makeDirectory()

    return mapOf(
        "Workspace-ID" to outWID.toString(),
        "Domain" to gServerDomain.toString(),
        "User-ID" to (outUID?.toString() ?: ""),
        "Reg-Code" to rcode,
        "Reg-Hash" to rhash,
    )
}

/**
 * Registers the administrator account and populates its workspace with test data.
 */
fun setupAdmin(db: DBConn) {
    val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
    val adminUID = UserID.fromString("admin")!!
    val devid = RandomID.fromString(ADMIN_PROFILE_DATA["devid"])!!
    val devkey = CryptoString.fromString(ADMIN_PROFILE_DATA["device.public"]!!)!!
    val fakeInfo = CryptoString.fromString("XSALSA20:ABCDEFG1234567890")!!
    addWorkspace(db, adminWID, adminUID, gServerDomain, ADMIN_PROFILE_DATA["passhash"]!!,
        "argon2id", "anXvadxtNJAYa2cUQFqKSQ", "m=65536,t=2,p=1",
        WorkspaceStatus.Active,WorkspaceType.Individual)
    addDevice(db, adminWID, devid, devkey, fakeInfo, DeviceStatus.Registered)?.let { throw it }
    deletePrereg(db, WAddress.fromParts(adminWID, gServerDomain))?.let { throw it }
}

/**
 * Registers a regular user account and populates its workspace with test data.
 */
fun setupUser(db: DBConn) {
    val userWID = RandomID.fromString(USER_PROFILE_DATA["wid"])!!
    val userUID = UserID.fromString(USER_PROFILE_DATA["uid"])!!
    val devid = RandomID.fromString(USER_PROFILE_DATA["devid"])!!
    val devkey = CryptoString.fromString(USER_PROFILE_DATA["device.public"]!!)!!
    val fakeInfo = CryptoString.fromString("XSALSA20:abcdefg1234567890")!!
    addWorkspace(db, userWID, userUID, gServerDomain, USER_PROFILE_DATA["passhash"]!!,
        "argon2id", "ejzAtaom5H1y6wnLHvrb7g", "m=65536,t=2,p=1",
        WorkspaceStatus.Active,WorkspaceType.Individual)
    addDevice(db, userWID, devid, devkey, fakeInfo, DeviceStatus.Registered)?.let { throw it }
    deletePrereg(db, WAddress.fromParts(userWID, gServerDomain))?.let { throw it }
}

/**
 * Contains all the state data used during test setup.
 *
 * @property config The config of the server in a ServerConfig instance
 * @property serverSetupData A String-String map containing data generated during server setup. Keys
 * used: "ovkey", "oskey", "oekey", "odkey", "admin_wid", "admin_regcode", "abuse_wid", and
 * "support_wid"
 * @property testPath The full filesystem path to the directory created for the test
 *
 * @see ServerConfig
 */
class SetupData(val config: ServerConfig, val serverSetupData: Map<String, String>,
                val testPath: String)

/**
 * Performs all the setup that most server tests will need and returns the path to the test
 * directory.
 */
fun setupTest(name: String): SetupData {
    val testpath = makeTestFolder(name)
    initLogging(Paths.get(testpath, "log.txt"), true)
    LocalFS.initialize(Paths.get(testpath, "topdir").toString())?.let { throw it }
    val lfs = LocalFS.get()
    listOf("wsp","out","tmp","keys").forEach { lfs.entry(MServerPath("/ $it")).makeDirectory() }

    val config = ServerConfig.load().getOrThrow()
    gServerDomain = Domain.fromString(config.getString("global.domain"))!!
    resetDB(config).getOrThrow()
    DBConn.initialize(config)?.let { throw it }
    val db = DBConn().connect().getOrThrow()
    val serverData = initDB(db.getConnection()!!)
    setupAdmin(db)


    return SetupData(config, serverData, testpath)
}

/**
 * Generate a test file containing nothing but zeroes. If the filename is not specified, a random
 * name will be generated. If the file size is not specified, the file will be between 1 and 10KB
 */
fun makeTestFile(fileDir: String, fileName: String? = null,
                 fileSize: Int? = null): Pair<String,Int> {

    val rng = SecureRandom()
    val realSize = fileSize ?: ((rng.nextInt(10) + 1) * 1024)

    val realName = if (fileName.isNullOrEmpty()) {
        "${Instant.now().epochSecond}.$realSize.${UUID.randomUUID().toString().lowercase()}"
    } else { fileName }

    val fHandle = File(Paths.get(fileDir, realName).toString())
    fHandle.writeBytes("0".repeat(realSize).toByteArray())

    return Pair(realName, realSize)
}

fun ServerResponse.assertReturnCode(c: Int) {
    if (code != c) throw ProtocolException(this.toString())
}

fun ServerResponse.assertField(field: String, validator: (v: String) -> Boolean) {
    if (!data.containsKey(field))
        throw ResourceNotFoundException("Missing field $field")
    assert(validator(data[field]!!))
}