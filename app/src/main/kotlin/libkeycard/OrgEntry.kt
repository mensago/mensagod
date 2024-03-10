package libkeycard

import keznacl.*
import java.util.*

/**
 * Represents one section of a keycard used by organizations. The list of permitted and required
 * fields can be found in the corresponding static properties of the class. For specific
 * information, please consult the Mensago Identity Services Guide and the Identity Services API
 * reference.
 */
class OrgEntry : Entry() {

    init {
        fields["Type"] = StringField("Organization")
        fields["Index"] = IntegerField(1)
        fields["Timestamp"] = TimestampField()

        // Time-To-Live is a validated field. When interacting with outside data, use ttlField(),
        // but when hardcoding known-good values like this case, a direct IntegerField assignment
        // is OK. 1 <= TTL <= 30.
        fields["Time-To-Live"] = IntegerField(14)

        // Default TTL for org entries. Expiration time 1 <= time <= 1095 days
        fields["Expires"] = DatestampField(Timestamp.plusDays(365))
    }

    /**
     * Returns the owner for the entry, which will be a domain string, or null if the required
     * fields are not populated.
     */
    override fun getOwner(): String? {
        return fields["Domain"]?.toString()
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
     * ssignature must be checked using `verify()` or `verify_chain()`.
     *
     * For an organizational entry to be compliant, it MUST have the following fields:
     *
     * - Type
     * - Index
     * - Name
     * - Domain
     * - Contact-Admin
     * - Primary-Verification-Key
     * - Encryption-Key
     * - Time-To-Live"
     * - Expires
     * - Timestamp
     *
     * Organizational entries MAY also have any of the following optional fields:
     *
     * - Contact-Abuse
     * - Contact-Support
     * - Language
     * - Secondary-Verification-Key
     */
    override fun isCompliant(): Throwable? {
        isDataCompliant()?.let { return it }

        if (fields["Index"]!!.toString() == "1") {
            // An organization's first (and hopefully only) root entry should *never* have a Revoke
            // field
            if (fields.containsKey("Revoke"))
                return BadFieldException("Root entry has a Revoke field")
        } else {
            // The only time an org entry which has an Index greater than one should not have a
            // custody signature or a previous hash is if the previous entry was revoked and, thus,
            // the current one is the new root for the organization.
            if (!fields.containsKey("Revoke")) {
                if (!hasAuthString("Custody-Signature"))
                    return BadFieldException(
                        "Non-root entry is missing required field Custody-Signature"
                    )
                if (!hasAuthString("Previous-Hash"))
                    return BadFieldException(
                        "Non-root entry is missing required field Previous-Hash"
                    )
            }
        }
        if (!hasAuthString("Hash"))
            return BadFieldException("Entry is missing required field Hash")
        if (!hasAuthString("Organization-Signature"))
            return BadFieldException("Entry is missing required field Organization-Signature")

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
     * Returns the full text of the entry, up to but not including the one specified. Passing a
     * null string will result in the entire entry being returned.
     *
     * The order for organization entries:
     *
     * - Custody-Signature
     * - Previous-Hash
     * - Hash
     * - Organization-Signature
     */
    override fun getFullText(sigLevel: String?): Result<String> {
        if (!fields.containsKey("Index"))
            return BadFieldException("Missing required field Index").toFailure()

        val lines = StringJoiner("\r\n")
        for (f in permittedFields) {
            if (fields[f] != null)
                lines.add("$f:${fields[f].toString()}")
        }

        val requirePrevious = getFieldInteger("Index")!! > 1 && !fields.containsKey("Revoke")

        when (sigLevel) {
            // This doesn't exist in an org entry
            "User-Signature" -> return BadValueException().toFailure()
            "Custody-Signature" -> {
                // We don't need to do anything else for the custody signature
            }

            "Previous-Hash" -> {
                if (signatures.containsKey("Custody-Signature"))
                    lines.add("Custody-Signature:${signatures["Custody-Signature"]}")
                else {
                    if (requirePrevious)
                        return ComplianceFailureException("Custody-Signature missing")
                            .toFailure()
                }
            }

            "Hash" -> {
                listOf("Custody-Signature", "Previous-Hash").forEach {
                    if (signatures.containsKey(it))
                        lines.add("$it:${signatures[it]}")
                    else {
                        if (requirePrevious)
                            return ComplianceFailureException("$it missing").toFailure()
                    }
                }
            }

            "Organization-Signature" -> {
                listOf("Custody-Signature", "Previous-Hash", "Hash").forEach {
                    if (signatures.containsKey(it))
                        lines.add("$it:${signatures[it]}")
                    else {
                        if (requirePrevious)
                            return ComplianceFailureException("$it missing").toFailure()
                    }
                }
            }

            null -> {
                listOf("Custody-Signature", "Previous-Hash", "Hash").forEach {
                    if (signatures.containsKey(it))
                        lines.add("$it:${signatures[it]}")
                    else {
                        if (requirePrevious)
                            return ComplianceFailureException("$it missing").toFailure()
                    }
                }
                if (signatures.containsKey("Organization-Signature"))
                    lines.add("Organization-Signature:${signatures["Organization-Signature"]}")
                else
                    return ComplianceFailureException("Organization-Signature missing")
                        .toFailure()
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
     */
    override fun chain(signingPair: SigningPair, expiration: Int):
            Result<Pair<Entry, Map<String, CryptoString>>> {

        if (!fields.containsKey("Primary-Verification-Key"))
            return ComplianceFailureException("Required field Primary-Verification-Key missing")
                .toFailure()

        if (!fields.containsKey("Encryption-Key"))
            return ComplianceFailureException("Required field Encryption-Key missing")
                .toFailure()
        if (!signatures.containsKey("Hash"))
            return ComplianceFailureException("Required auth string Hash missing").toFailure()

        val outMap = mutableMapOf<String, CryptoString>()
        val outEntry = copy().getOrElse { return it.toFailure() }


        val signAlgo = getVerificationKey("Primary-Verification-Key")
            ?: return BadFieldValueException("Bad Primary-Verification-Key").toFailure()
        val newSPair = SigningPair.generate(signAlgo.getType()!!)
            .getOrElse { return it.toFailure() }
        outMap["primary.public"] = newSPair.pubKey
        outMap["primary.private"] = newSPair.privKey
        outEntry.setField("Primary-Verification-Key", newSPair.pubKey.value)

        val encAlgo = getEncryptionKey("Encryption-Key")
            ?: return BadFieldValueException("Bad Encryption-Key").toFailure()

        val newEPair = EncryptionPair.generate(encAlgo.getType()!!)
            .getOrElse { return it.toFailure() }
        outMap["encryption.public"] = newEPair.pubKey
        outMap["encryption.private"] = newEPair.privKey
        outEntry.setField("Encryption-Key", newEPair.pubKey.value)

        outEntry.setField(
            "Secondary-Verification-Key",
            fields["Primary-Verification-Key"]!!.toString()
        )
        outEntry.addAuthString("Previous-Hash", getAuthString("Hash")!!)

        if (expiration <= 0) setExpires(366)
        else setExpires(expiration)

        outEntry.sign("Custody-Signature", signingPair)?.let { return it.toFailure() }
        val hashAlgo = getHash("Hash")
            ?: return BadFieldValueException("Bad Hash").toFailure()

        outEntry.hash(hashAlgo.getType()!!)?.let { return it.toFailure() }
        outEntry.sign("Organization-Signature", newSPair)?.let { return it.toFailure() }

        return Pair(outEntry, outMap).toSuccess()
    }

    /**
     * Verifies the chain of custody between the current Entry instance and the provided entry. This
     * call will succeed only if the current entry was instantiated as a result of calling the
     * previous one's `chain()` method, i.e. the Index field of `previous` is expected to be 1 less
     * than that of the instance or an OutOfOrderException will be returned. If either entry is
     * invalid, an InvalidDataException will be returned. false will be returned if the chain of
     * custody hash does not match.
     */
    override fun verifyChain(previous: Entry): Result<Boolean> {
        if (previous !is OrgEntry) return TypeCastException().toFailure()

        val prevIndex = previous.getFieldInteger("Index")
            ?: return MissingDataException("previous Index field missing").toFailure()

        val currentIndex = getFieldInteger("Index")
            ?: return MissingDataException("Index field missing").toFailure()
        if (prevIndex != currentIndex - 1)
            return ComplianceFailureException("Non-sequential entries").toFailure()

        val verKeyStr =
            previous.getFieldString("Primary-Verification-Key")
                ?: return MissingDataException("Primary-Verification-Key field missing").toFailure()
        val verKey = VerificationKey.fromString(verKeyStr).getOrElse { return it.toFailure() }

        return verifySignature("Custody-Signature", verKey)
    }

    /**
     * This method is called when the current entry must be revoked because one or more keys were
     * compromised. A new root entry is created with a `Revoke` field containing the hash of the
     * current one and an `Index` which is, like `chain()`, one greater than the current entry.
     */
    override fun revoke(expiration: Int): Result<Pair<Entry, Map<String, CryptoString>>> {
        val outMap = mutableMapOf<String, CryptoString>()
        val outEntry = copy().getOrElse { return it.toFailure() }

        val signAlgo = getVerificationKey("Primary-Verification-Key")
            ?: return BadFieldValueException("Bad Primary-Verification-Key").toFailure()
        val newSPair = SigningPair.generate(signAlgo.getType()!!)
            .getOrElse { return it.toFailure() }
        outMap["primary.public"] = newSPair.pubKey
        outMap["primary.private"] = newSPair.privKey
        outEntry.setField("Primary-Verification-Key", newSPair.pubKey.value)

        val encAlgo = getEncryptionKey("Encryption-Key")
            ?: return BadFieldValueException("Bad Encryption-Key").toFailure()

        val newEPair = EncryptionPair.generate(encAlgo.getType()!!)
            .getOrElse { return it.toFailure() }
        outMap["encryption.public"] = newSPair.pubKey
        outMap["encryption.private"] = newSPair.privKey
        outEntry.setField("Encryption-Key", newEPair.pubKey.value)

        if (expiration <= 0) setExpires(366)
        else setExpires(expiration)

        // This new entry has no custody signature--it's a new root entry

        val hash = getHash("Hash") ?: return BadFieldValueException("Bad Hash").toFailure()

        outEntry.setField("Revoke", hash.toString())
        outEntry.hash(hash.getType()!!)?.let { return it.toFailure() }
        outEntry.sign("Organization-Signature", newSPair)?.let { return it.toFailure() }

        return Pair(outEntry, outMap).toSuccess()
    }

    companion object {
        // The order of these strings matters, as getText depends on it. The Type field should
        // always be first in an entry.
        val permittedFields = listOf(
            "Type",
            "Index",
            "Name",
            "Domain",
            "Contact-Admin",
            "Contact-Abuse",
            "Contact-Support",
            "Language",
            "Primary-Verification-Key",
            "Secondary-Verification-Key",
            "Encryption-Key",
            "Time-To-Live",
            "Expires",
            "Timestamp",
            "Revoke",
        )
        val requiredFields = listOf(
            "Type",
            "Index",
            "Name",
            "Domain",
            "Contact-Admin",
            "Primary-Verification-Key",
            "Encryption-Key",
            "Time-To-Live",
            "Expires",
            "Timestamp",
        )

        /**
         * Instantiates an OrgEntry object from a string. The data for each field is validated, but
         * a successful call does not imply compliance.
         */
        fun fromString(s: String): Result<OrgEntry> {
            /*
            160 is a close approximation. It includes the names of all required fields and the
            minimum length for any variable-length fields, including keys. It's a good, quick way
            of ruling out obviously bad data.
             */
            if (s.length < 160) {
                return BadValueException().toFailure()
            }

            val out = OrgEntry()
            for (rawLine in s.split("\r\n")) {
                val line = rawLine.trim()
                if (line.isEmpty()) continue

                val parts = line.split(":", limit = 2)
                if (parts.size != 2) {
                    return BadFieldValueException(line).toFailure()
                }

                if (parts[1].length > 6144) {
                    return RangeException("Field ${parts[0]} may not be longer than 6144 bytes")
                        .toFailure()
                }

                val fieldName = parts[0]
                val fieldValue = parts[1]
                when (fieldName) {
                    "Custody-Signature",
                    "Organization-Signature",
                    "Previous-Hash",
                    "Hash" -> {
                        val cs = CryptoString.fromString(fieldValue)
                            ?: return BadFieldValueException(fieldName).toFailure()
                        out.addAuthString(fieldName, cs)
                        continue
                    }
                }

                val field = EntryField.fromStrings(fieldName, fieldValue)
                if (field.isFailure) return field.exceptionOrNull()!!.toFailure()

                out.setField(fieldName, fieldValue)?.let { return it.toFailure() }
            }

            return out.toSuccess()
        }
    }
}