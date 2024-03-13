package testsupport

import keznacl.Argon2idPassword
import keznacl.CryptoString
import keznacl.EncryptionPair
import keznacl.SigningPair
import libkeycard.*
import libmensago.MServerPath
import libmensago.ResourceNotFoundException
import libmensago.ServerResponse
import libmensago.resolver.KCResolver
import mensagod.*
import mensagod.dbcmds.*
import mensagod.handlers.DeviceStatus
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

/** Returns the canonical version of the path specified. */
fun getPathForTest(testName: String): String? {
    return try {
        Paths.get("build", "testfiles", testName).toAbsolutePath().toString()
    } catch (e: Exception) {
        null
    }
}

/** Creates a new test folder for file-based tests and returns the top-level path created. */
fun makeTestFolder(name: String): String {

    val testdirStr = getPathForTest(name)!!
    val topdirStr = Paths.get(testdirStr, "topdir").toString()
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
    rootEntry.setField(
        "Contact-Admin",
        "c590b44c-798d-4055-8d72-725a7942f3f6/example.com"
    )
    rootEntry.setField("Language", "en")
    rootEntry.setField("Domain", "example.com")
    rootEntry.setField("Primary-Verification-Key", initialOSPair.pubKey.toString())
    rootEntry.setField("Encryption-Key", initialOEPair.pubKey.toString())

    rootEntry.isDataCompliant()?.let { throw it }
    rootEntry.hash()?.let { throw it }
    rootEntry.sign("Organization-Signature", initialOSPair)?.let { throw it }
    rootEntry.verifySignature("Organization-Signature", initialOSPair).getOrThrow()
    rootEntry.isCompliant()?.let { throw it }

    val orgCard = Keycard.new("Organization")!!
    orgCard.entries.add(rootEntry)

    var stmt = db.prepareStatement(
        """INSERT INTO keycards(owner,creationtime,index,entry,fingerprint)
        VALUES('organization',?,?,?,?);"""
    )
    stmt.setString(1, rootEntry.getFieldString("Timestamp")!!)
    stmt.setInt(2, rootEntry.getFieldInteger("Index")!!)
    stmt.setString(3, rootEntry.getFullText(null).getOrThrow())
    stmt.setString(4, rootEntry.getAuthString("Hash")!!.toString())
    stmt.execute()

    stmt = db.prepareStatement(
        """INSERT INTO orgkeys(creationtime,pubkey,privkey,purpose,fingerprint)
        VALUES(?,?,?,'encrypt',?);"""
    )
    stmt.setString(1, rootEntry.getFieldString("Timestamp")!!)
    stmt.setString(2, initialOEPair.pubKey.toString())
    stmt.setString(3, initialOEPair.privKey.toString())
    stmt.setString(4, initialOEPair.pubKey.hash().getOrThrow().toString())
    stmt.execute()

    stmt = db.prepareStatement(
        """INSERT INTO orgkeys(creationtime,pubkey,privkey,purpose,fingerprint)
        VALUES(?,?,?,'sign',?);"""
    )
    stmt.setString(1, rootEntry.getFieldString("Timestamp")!!)
    stmt.setString(2, initialOSPair.pubKey.toString())
    stmt.setString(3, initialOSPair.privKey.toString())
    stmt.setString(4, initialOSPair.pubKey.hash().getOrThrow().toString())
    stmt.execute()

    // Now that we've added the organization's root keycard entry and keys, chain a new entry and
    // add it to the database.
    val keys = orgCard.chain(initialOSPair, 365).getOrThrow()

    val newEntry = orgCard.entries[1]

    stmt = db.prepareStatement(
        """INSERT INTO keycards(owner,creationtime,index,entry,fingerprint)
        VALUES('organization',?,?,?,?);"""
    )
    stmt.setString(1, newEntry.getFieldString("Timestamp")!!)
    stmt.setInt(2, newEntry.getFieldInteger("Index")!!)
    stmt.setString(3, newEntry.getFullText(null).getOrThrow())
    stmt.setString(4, newEntry.getAuthString("Hash")!!.toString())
    stmt.execute()

    stmt = db.prepareStatement(
        """UPDATE orgkeys SET creationtime=?,pubkey=?,privkey=?,fingerprint=?
        WHERE purpose='encrypt';"""
    )
    stmt.setString(1, newEntry.getFieldString("Timestamp")!!)
    stmt.setString(2, keys["encryption.public"].toString())
    stmt.setString(3, keys["encryption.private"].toString())
    stmt.setString(4, keys["encryption.public"]!!.hash().getOrThrow().toString())
    stmt.execute()

    stmt = db.prepareStatement(
        """UPDATE orgkeys SET creationtime=?,pubkey=?,privkey=?,fingerprint=?
        WHERE purpose='sign';"""
    )
    stmt.setString(1, newEntry.getFieldString("Timestamp")!!)
    stmt.setString(2, keys["primary.public"].toString())
    stmt.setString(3, keys["primary.private"].toString())
    stmt.setString(4, keys["primary.public"]!!.hash().getOrThrow().toString())
    stmt.execute()

    stmt = db.prepareStatement(
        """INSERT INTO orgkeys(creationtime,pubkey,privkey,purpose,fingerprint)
        VALUES(?,?,?,'altsign',?);"""
    )
    stmt.setString(1, rootEntry.getFieldString("Timestamp")!!)
    stmt.setString(2, initialOSPair.pubKey.toString())
    stmt.setString(3, initialOSPair.privKey.toString())
    stmt.setString(4, initialOSPair.pubKey.hash().getOrThrow().toString())
    stmt.execute()

    // Preregister the admin account

    val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"]!!)!!
    stmt = db.prepareStatement(
        """INSERT INTO prereg(wid,uid,domain,regcode) 
        VALUES(?,'admin','example.com',?);"""
    )
    stmt.setString(1, adminWID.toString())
    stmt.setString(2, ADMIN_PROFILE_DATA["reghash"]!!)
    stmt.execute()

    // Set up abuse/support forwarding to admin

    stmt = db.prepareStatement(
        """INSERT INTO workspaces(wid,uid,domain,password,passtype,status,wtype) 
        VALUES(?,'abuse','example.com','-', '','active','alias');"""
    )
    stmt.setString(1, adminWID.toString())
    stmt.execute()

    stmt = db.prepareStatement(
        """INSERT INTO workspaces(wid,uid,domain,password,passtype,status,wtype) 
        VALUES(?,'support','example.com','-', '','active','alias');"""
    )
    stmt.setString(1, adminWID.toString())
    stmt.execute()

    return mutableMapOf(
        "ovkey" to keys["primary.public"].toString(),
        "oskey" to keys["primary.private"].toString(),
        "oekey" to keys["encryption.public"].toString(),
        "odkey" to keys["encryption.private"].toString(),
        "admin_wid" to adminWID.toString(),
        "admin_regcode" to ADMIN_PROFILE_DATA["regcode"]!!,
    )
}

/** Test setup command to preregister a user */
fun preregUser(
    db: DBConn, uid: String? = null, regcode: String? = null, reghash: String? = null,
    wid: String? = null
): Map<String, String> {

    val rcode = regcode ?: gRegCodeGenerator.getPassphrase(
        ServerConfig.get().getInteger("security.diceware_wordcount")!!
    )
    val rhash = reghash ?: Argon2idPassword().updateHash(rcode).getOrThrow()

    val outWID = RandomID.fromString(wid) ?: RandomID.generate()
    val outUID = UserID.fromString(uid)
    preregWorkspace(db, outWID, outUID, gServerDomain, rhash)?.let { throw it }
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
    addWorkspace(
        db, adminWID, adminUID, gServerDomain, ADMIN_PROFILE_DATA["passhash"]!!,
        "argon2id", "anXvadxtNJAYa2cUQFqKSQ", "m=65536,t=2,p=1",
        WorkspaceStatus.Active, WorkspaceType.Individual
    )?.let { throw it }
    addDevice(db, adminWID, devid, devkey, fakeInfo, DeviceStatus.Registered)?.let { throw it }
    deletePrereg(db, WAddress.fromParts(adminWID, gServerDomain))?.let { throw it }
}

/**
 * Sets up the admin account's keycard. Just needed for tests that use keycards and those which
 * cover more advanced functionality. If `chain` is true, a second entry in the admin's keycard is
 * created and all necessary verification checks are made.
 */
fun setupKeycard(db: DBConn, chain: Boolean, profileData: MutableMap<String, String>) {
    val userEntry = UserEntry.fromString(profileData["keycard"]!!).getOrThrow()
    val card = Keycard.new("User")!!
    card.entries.add(userEntry)
    card.current!!.isDataCompliant()?.let { throw it }
    val serverPair = getPrimarySigningPair(db).getOrThrow()
    card.current!!.sign("Organization-Signature", serverPair)?.let { throw it }

    val orgEntry = OrgEntry.fromString(getEntries(db, null, 0U).getOrThrow()[0])
        .getOrThrow()
    val prevHash = orgEntry.getAuthString("Previous-Hash")!!
    card.current!!.addAuthString("Previous-Hash", prevHash)
    card.current!!.hash()?.let { throw it }
    val adminCRSPair = SigningPair.fromStrings(
        profileData["crsigning.public"]!!,
        profileData["crsigning.private"]!!
    ).getOrThrow()
    card.current!!.sign("User-Signature", adminCRSPair)?.let { throw it }
    card.current!!.isCompliant()?.let { throw it }
    addEntry(db, card.current!!)?.let { throw it }

    if (!chain) return

    val newKeys = card.chain(adminCRSPair).getOrThrow()
    card.current!!.sign("Organization-Signature", serverPair)?.let { throw it }
    card.current!!.hash()?.let { throw it }
    card.current!!.sign("User-Signature", adminCRSPair)?.let { throw it }
    card.current!!.isCompliant()?.let { throw it }
    addEntry(db, card.current!!)?.let { throw it }
    assert(card.verify().getOrThrow())

    profileData["crsigning.public"] = newKeys["crsigning.public"]!!.toString()
    profileData["crsigning.private"] = newKeys["crsigning.private"]!!.toString()
    profileData["crencryption.public"] = newKeys["crencryption.public"]!!.toString()
    profileData["crencryption.private"] = newKeys["crencryption.private"]!!.toString()
    profileData["signing.public"] = newKeys["signing.public"]!!.toString()
    profileData["signing.private"] = newKeys["signing.private"]!!.toString()
    profileData["encryption.public"] = newKeys["encryption.public"]!!.toString()
    profileData["encryption.private"] = newKeys["encryption.private"]!!.toString()
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
    addWorkspace(
        db, userWID, userUID, gServerDomain, USER_PROFILE_DATA["passhash"]!!,
        "argon2id", "ejzAtaom5H1y6wnLHvrb7g", "m=65536,t=2,p=1",
        WorkspaceStatus.Active, WorkspaceType.Individual
    )?.let { throw it }
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
class SetupData(
    val config: ServerConfig, val serverSetupData: Map<String, String>,
    val testPath: String
)

/**
 * Performs all the setup that most server tests will need and returns the path to the test
 * directory. This means resetting the server database and setting up the admin account for login.
 * It does NOT set up a second user, however, nor does it upload the admin account's keycard. These
 * tasks will require a call to setupUser() and setupKeycard() respectively.
 */
fun setupTest(name: String): SetupData {
    val testpath = makeTestFolder(name)
    initLogging(Paths.get(testpath, "log.txt"), true)
    LocalFS.initialize(Paths.get(testpath, "topdir").toString())?.let { throw it }
    val lfs = LocalFS.get()
    listOf("wsp", "out", "tmp", "keys").forEach { lfs.entry(MServerPath("/ $it")).makeDirectory() }
    KCResolver.dns = FakeDNSHandler()

    val config = ServerConfig.load().getOrThrow()
    gServerDomain = Domain.fromString(config.getString("global.domain"))!!
    gServerAddress = WAddress.fromParts(gServerDevID, gServerDomain)
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
fun makeTestFile(
    fileDir: String, fileName: String? = null,
    fileSize: Int? = null
): Pair<String, Int> {

    val rng = SecureRandom()
    val realSize = fileSize ?: ((rng.nextInt(10) + 1) * 1024)

    val realName = if (fileName.isNullOrEmpty()) {
        "${Instant.now().epochSecond}.$realSize.${UUID.randomUUID().toString().lowercase()}"
    } else {
        fileName
    }

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

class TestFailureException(message: String = "") : Exception(message)
