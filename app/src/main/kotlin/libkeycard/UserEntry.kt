package libkeycard

import keznacl.*
import java.util.*

/**
 * Represents one section of a keycard used by people. The list of permitted and required
 * fields can be found in the corresponding static properties of the class. For specific
 * information, please consult the Mensago Identity Services Guide and the Identity Services API
 * reference.
 */
class UserEntry : Entry() {

    init {
        fields["Type"] = StringField("User")
        fields["Index"] = IntegerField(1)
        fields["Timestamp"] = TimestampField()

        // Time-To-Live is a validated field. When interacting with outside data, use ttlField(),
        // but when hardcoding known-good values like this case, a direct IntegerField assignment
        // is OK. 1 <= TTL <= 30.
        fields["Time-To-Live"] = IntegerField(14)

        // Default TTL for org entries. Expiration time 1 <= time <= 1095 days
        fields["Expires"] = DatestampField(Timestamp.plusDays(30))
    }

    /**
     * Returns the owner for the entry, which will be a string containing a workspace address. It
     * will return null if the required fields are not populated.
     */
    override fun getOwner(): String? {
        val wid = fields["Workspace-ID"] as StringField? ?: return null
        val domain = fields["Domain"] as StringField? ?: return null
        return "$wid/$domain"
    }

    /**
     * Checks the formatting of the regular fields in the entry and returns false if a field is
     * missing or does not comply with the spec. This method is usually called to ensure that the
     * data in an entry is valid before proceeding with the signing and hashing process.
     */
    override fun isDataCompliant(): Throwable? {
        for (f in requiredFields) {
            if (!fields.containsKey(f)) return BadFieldException("Missing field $f is required")
        }
        return null
    }

    /**
     * Returns a Throwable if the entry has any compliance issues, including missing or bad hashes
     * and/or signatures. This method performs all the checks made in `isDataCompliant()` and more.
     * Note that only the format of signatures and hashes are checked. The validity of a hash or
     * signature must be checked using `verify()` or `verify_chain()`.
     *
     * For a user entry to be compliant, it MUST have the following fields:
     *
     * - Type
     * - Index
     * - Workspace-ID
     * - Domain
     * - Contact-Request-Verification-Key
     * - Contact-Request-Encryption-Key
     * - Verification-Key
     * - Encryption-Key
     * - Time-To-Live"
     * - Expires
     * - Timestamp
     *
     * User entries MAY also have a Name, User-ID, or Local-User-ID field, although these are
     * optional.
     */
    override fun isCompliant(): Throwable? {
        val dataComplianceError = isDataCompliant()
        if (dataComplianceError != null) return dataComplianceError

        if (fields["Index"]!!.toString() == "1") {
            // A user's first root keycard should *never* have a Revoke field.
            if (fields.containsKey("Revoke"))
                return BadFieldException("Root entry has a Revoke field")
        } else {
            // A replacement root entry will have a Revoke field, in which case it will not have a
            // custody signature, but it will have an index greater than 1.
            if (!fields.containsKey("Revoke")) {
                if (!hasAuthString("Custody-Signature"))
                    return BadFieldException(
                        "Non-root entry is missing required field Custody-Signature"
                    )
            }
        }
        listOf("Organization-Signature", "Previous-Hash", "Hash", "User-Signature").forEach {
            if (!hasAuthString(it))
                return BadFieldException("Entry is missing required field $it")
        }

        return null
    }

    /** Returns the body text of the entry */
    override fun getText(): String {

        val lines = StringJoiner("\r\n")
        for (f in permittedFields) {
            if (fields[f] != null)
                lines.add("$f:${fields[f].toString()}")
        }
        lines.add("")
        return lines.toString()
    }

    /**
     * Returns the full text of the entry, up to but not including the one specified. Passing a null
     * string will result in the entire entry being returned.
     *
     * The order for user entries:
     *
     * - Custody-Signature
     * - Organization-Signature
     * - Previous-Hash
     * - Hash
     * - User-Signature
     */
    override fun getFullText(sigLevel: String?): Result<String> {
        if (!fields.containsKey("Index"))
            return BadFieldException("Missing required field Index").toFailure()

        val lines = StringJoiner("\r\n")
        for (f in permittedFields) {
            if (fields[f] != null)
                lines.add("$f:${fields[f].toString()}")
        }

        val requirePrevious = getFieldInteger("Index")!! > 1 &&
                !fields.containsKey("Revoke")

        when (sigLevel) {
            "Custody-Signature" -> {
                // We don't need to do anything else for the custody signature
            }

            "Organization-Signature" -> {
                if (signatures.containsKey("Custody-Signature"))
                    lines.add("Custody-Signature:${signatures["Custody-Signature"]}")
                else {
                    if (requirePrevious)
                        return ComplianceFailureException("Custody-Signature missing").toFailure()
                }
            }

            "Previous-Hash" -> {
                listOf("Custody-Signature", "Organization-Signature").forEach {
                    if (signatures.containsKey(it))
                        lines.add("$it:${signatures[it]}")
                    else {
                        if (requirePrevious)
                            return ComplianceFailureException("$it missing").toFailure()
                    }
                }
            }

            "Hash" -> {
                listOf("Custody-Signature", "Organization-Signature", "Previous-Hash").forEach {
                    if (signatures.containsKey(it))
                        lines.add("$it:${signatures[it]}")
                    else {
                        if (requirePrevious)
                            return ComplianceFailureException("$it missing").toFailure()
                    }
                }
            }

            "User-Signature" -> {
                listOf(
                    "Custody-Signature", "Organization-Signature", "Previous-Hash",
                    "Hash"
                ).forEach {
                    if (signatures.containsKey(it))
                        lines.add("$it:${signatures[it]}")
                    else {
                        if (requirePrevious)
                            return ComplianceFailureException("$it missing").toFailure()
                    }
                }
            }

            null -> {
                listOf(
                    "Custody-Signature", "Organization-Signature", "Previous-Hash", "Hash",
                    "User-Signature"
                ).forEach {
                    if (signatures.containsKey(it))
                        lines.add("$it:${signatures[it]}")
                    else {
                        if (requirePrevious)
                            return ComplianceFailureException("$it missing").toFailure()
                    }
                }
            }

            else -> return BadValueException().toFailure()
        }
        lines.add("")
        return lines.toString().toSuccess()
    }

    /**
     * Internal method required by subclasses which returns true if the field is one of those
     * permitted for the entry type.
     */
    override fun isFieldAllowed(fieldName: String): Boolean {
        return permittedFields.contains(fieldName)
    }

    /**
     * Creates a new Entry object with new keys and a custody signature. It requires the signing
     * keypair used for the entry so that the Custody-Signature field is generated correctly. An
     * expiration period for the new entry may be specified. If the default expiration value is
     * used, the default for the entry type is used.
     *
     * The signing and hashing requirements are different for user entries, so unlike
     * OrgEntry::chain(), the UserEntry instance returned by this call is not compliant. In order
     * to be fully compliant, the UserEntry data must be signed by the organization's server,
     * add the hash of its preceding keycard entry, have its hash calculated and added, and then
     * signed by the user. Fortunately, this is actually easier than it sounds, amounting to a
     * call to addAuthString(), hash(), and then sign() with the same signing pair passed to
     * chain() -- the user's Contact Request signing pair.
     */
    override fun chain(signingPair: SigningPair, expiration: Int):
            Result<Pair<Entry, Map<String, CryptoString>>> {

        if (!fields.containsKey("Contact-Request-Verification-Key"))
            return ComplianceFailureException(
                "Required field Contact-Request-Verification-Key missing"
            ).toFailure()
        if (!fields.containsKey("Contact-Request-Encryption-Key"))
            return ComplianceFailureException(
                "Required field Contact-Request-Encryption-Key missing"
            ).toFailure()
        if (!signatures.containsKey("Hash"))
            return ComplianceFailureException("Required auth string Hash missing").toFailure()

        val outMap = mutableMapOf<String, CryptoString>()
        val outEntry = copy().getOrElse { return it.toFailure() }


        val signAlgo = getVerificationKey("Contact-Request-Verification-Key")
            ?: return BadFieldValueException("Bad Contact-Request-Verification-Key").toFailure()
        val newCRSPair =
            SigningPair.generate(signAlgo.getType()!!).getOrElse { return it.toFailure() }
        outMap["crsigning.public"] = newCRSPair.pubKey
        outMap["crsigning.private"] = newCRSPair.privKey
        outEntry.setField("Contact-Request-Verification-Key", newCRSPair.pubKey.value)

        val encAlgo = getEncryptionKey("Contact-Request-Encryption-Key")
            ?: return BadFieldValueException("Bad Contact-Request-Encryption-Key").toFailure()
        val newCREPair =
            EncryptionPair.generate(encAlgo.getType()!!).getOrElse { return it.toFailure() }
        outMap["crencryption.public"] = newCREPair.pubKey
        outMap["crencryption.private"] = newCREPair.privKey
        outEntry.setField("Contact-Request-Encryption-Key", newCREPair.pubKey.value)

        val newSPair =
            SigningPair.generate(signAlgo.getType()!!).getOrElse { return it.toFailure() }
        outMap["signing.public"] = newSPair.pubKey
        outMap["signing.private"] = newSPair.privKey
        outEntry.setField("Verification-Key", newSPair.pubKey.value)

        val newEPair =
            EncryptionPair.generate(encAlgo.getType()!!).getOrElse { return it.toFailure() }
        outMap["encryption.public"] = newEPair.pubKey
        outMap["encryption.private"] = newEPair.privKey
        outEntry.setField("Encryption-Key", newEPair.pubKey.value)

        outEntry.addAuthString("Previous-Hash", getAuthString("Hash")!!)

        if (expiration <= 0) setExpires(30)
        else setExpires(expiration)

        outEntry.sign("Custody-Signature", signingPair)?.let { return it.toFailure() }

        return Pair(outEntry, outMap).toSuccess()
    }

    /**
     * Verifies the chain of custody between the current Entry instance and the provided entry. This
     * is a fairly expensive operation and should be performed only when necessary. This call checks
     * compliance on the entry passed to this method. Please ensure you are starting with a
     * fully-compliant entry (via isCompliant()) before calling this.
     *
     * Unlike the OrgEntry version of this method, this implementation may take an OrgEntry as a
     * parameter. This is because the chain of hashes used to verify keycards is a tree. User
     * keycards are chained to different points on the organization's keycard similar to branches
     * extending from a central trunk.
     *
     * A UserEntry expects to be verified with the entry appearing immediately before itself in the
     * tree. For user entries, this means that the index of the previous entry will be 1 less than
     * the current one. An OutOfOrderException will be returned if this is not the case. Verifying
     * the chain between a root user entry and its attachment point in the organization's keycard
     * has no such restriction; only the corresponding hash entries need to match.
     *
     *  If either entry is invalid, an InvalidDataException will be returned. false will be returned
     *  if the chain of custody hash does not match.
     *
     */
    override fun verifyChain(previous: Entry): Result<Boolean> {

        if (!signatures.containsKey("Previous-Hash"))
            return ComplianceFailureException(
                "Required auth string Previous-Hash missing"
            ).toFailure()
        if (!fields.containsKey("Index"))
            return ComplianceFailureException("Required field Index missing").toFailure()

        // If the current entry revokes the previous one, there can be no chain verification
        if (isRevoked()) return RevokedEntryException().toFailure()

        val complianceError = previous.isCompliant()
        if (complianceError != null) return complianceError.toFailure()

        if (previous.getAuthString("Hash")!!.toString() !=
            getAuthString("Previous-Hash")!!.toString()
        )
            return HashMismatchException().toFailure()

        val className = previous.javaClass.toString()
        val result = when {
            className.endsWith("UserEntry") -> {
                val selfIndex = getFieldInteger("Index")!!
                if (selfIndex == 1)
                    return OutOfOrderException().toFailure()

                if (previous.getFieldInteger("Index")!! != selfIndex - 1)
                    return OutOfOrderException().toFailure()
                val verKeyStr = previous.getFieldString(
                    "Contact-Request-Verification-Key"
                )!!
                val verKey = VerificationKey.fromString(verKeyStr)
                    .getOrElse {
                        return BadFieldValueException("Bad CR verification key").toFailure()
                    }

                verifySignature("Custody-Signature", verKey)
            }

            className.endsWith("OrgEntry") -> {
                val verKeyStr = previous.getFieldString("Primary-Verification-Key")!!
                val verKey = VerificationKey.fromString(verKeyStr)
                    .getOrElse {
                        return BadFieldValueException("Bad org verification key").toFailure()
                    }

                verifySignature("Organization-Signature", verKey)
            }

            else -> return EntryTypeException().toFailure()
        }

        return result
    }

    /**
     * This method is called when the current entry must be revoked because one or more keys were
     * compromised. A new root entry is created with a `Revoke` field containing the hash of the
     * current one and an `Index` which is, like `chain()`, one greater than the current entry.
     */
    override fun revoke(expiration: Int): Result<Pair<Entry, Map<String, CryptoString>>> {

        if (!fields.containsKey("Contact-Request-Verification-Key"))
            return ComplianceFailureException(
                "Required field Contact-Request-Verification-Key missing"
            ).toFailure()
        if (!fields.containsKey("Contact-Request-Encryption-Key"))
            return ComplianceFailureException(
                "Required field Contact-Request-Encryption-Key missing"
            ).toFailure()
        if (!signatures.containsKey("Hash"))
            return ComplianceFailureException("Required auth string Hash missing").toFailure()

        val outMap = mutableMapOf<String, CryptoString>()
        val outEntry = copy().getOrElse { return it.toFailure() }


        val signAlgo = getVerificationKey("Contact-Request-Verification-Key")
            ?: return BadFieldValueException("Bad Contact-Request-Verification-Key").toFailure()
        val newCRSPair =
            SigningPair.generate(signAlgo.getType()!!).getOrElse { return it.toFailure() }
        outMap["crsigning.public"] = newCRSPair.pubKey
        outMap["crsigning.private"] = newCRSPair.privKey
        outEntry.setField("Contact-Request-Verification-Key", newCRSPair.pubKey.value)

        val encAlgo = getEncryptionKey("Contact-Request-Encryption-Key")
            ?: return BadFieldValueException("Bad Contact-Request-Encryption-Key").toFailure()
        val newCREPair =
            EncryptionPair.generate(encAlgo.getType()!!).getOrElse { return it.toFailure() }
        outMap["crencryption.public"] = newCRSPair.pubKey
        outMap["crencryption.private"] = newCRSPair.privKey
        outEntry.setField("Contact-Request-Encryption-Key", newCREPair.pubKey.value)

        val newSPair =
            SigningPair.generate(signAlgo.getType()!!).getOrElse { return it.toFailure() }
        outMap["signing.public"] = newSPair.pubKey
        outMap["signing.private"] = newSPair.privKey
        outEntry.setField("Verification-Key", newSPair.pubKey.value)

        val newEPair =
            EncryptionPair.generate(encAlgo.getType()!!).getOrElse { return it.toFailure() }
        outMap["encryption.public"] = newSPair.pubKey
        outMap["encryption.private"] = newSPair.privKey
        outEntry.setField("Encryption-Key", newEPair.pubKey.value)

        outEntry.setField("Revoke", getAuthString("Hash").toString())
        outEntry.addAuthString("Previous-Hash", getAuthString("Hash")!!)

        if (expiration <= 0) setExpires(30)
        else setExpires(expiration)

        return Pair(outEntry, outMap).toSuccess()
    }

    companion object {
        val permittedFields = mutableListOf(
            "Type",
            "Index",
            "Name",
            "User-ID",
            "Local-User-ID",
            "Workspace-ID",
            "Domain",
            "Contact-Request-Verification-Key",
            "Contact-Request-Encryption-Key",
            "Encryption-Key",
            "Verification-Key",
            "Time-To-Live",
            "Expires",
            "Timestamp",
            "Revoke",
        )
        val requiredFields = mutableListOf(
            "Type",
            "Index",
            "Workspace-ID",
            "Domain",
            "Contact-Request-Verification-Key",
            "Contact-Request-Encryption-Key",
            "Encryption-Key",
            "Verification-Key",
            "Time-To-Live",
            "Expires",
            "Timestamp",
        )

        /**
         * Instantiates an UserEntry object from a string. The data for each field is validated, but a
         * successful call does not imply compliance.
         */
        fun fromString(s: String): Result<UserEntry> {
            /*
            160 is a close approximation. It includes the names of all required fields and the minimum
            length for any variable-length fields, including keys. It's a good, quick way of ruling out
             obviously bad data.
             */
            if (s.length < 160)
                return BadValueException().toFailure()

            val out = UserEntry()
            for (rawLine in s.split("\r\n")) {
                val line = rawLine.trim()
                if (line.isEmpty()) continue

                val parts = line.split(":", limit = 2)
                if (parts.size != 2)
                    return BadFieldValueException(line).toFailure()

                if (parts[1].length > 6144)
                    return RangeException("Field ${parts[0]} may not be longer than 6144 bytes")
                        .toFailure()

                val fieldName = parts[0]
                val fieldValue = parts[1]
                when (fieldName) {
                    "Custody-Signature",
                    "Organization-Signature",
                    "Previous-Hash",
                    "Hash",
                    "User-Signature" -> {
                        val cs = CryptoString.fromString(fieldValue)
                            ?: return BadFieldValueException(fieldName).toFailure()
                        out.addAuthString(fieldName, cs)
                        continue
                    }
                }

                EntryField.fromStrings(fieldName, fieldValue).onFailure { return it.toFailure() }
                out.setField(fieldName, fieldValue)?.let { return it.toFailure() }
            }

            return out.toSuccess()
        }
    }
}