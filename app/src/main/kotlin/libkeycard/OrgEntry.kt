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
        val dataComplianceError = isDataCompliant()
        if (dataComplianceError != null) return dataComplianceError

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
            return Result.failure(BadFieldException("Missing required field Index"))

        val lines = StringJoiner("\r\n")
        for (f in permittedFields) {
            if (fields[f] != null)
                lines.add("$f:${fields[f].toString()}")
        }

        val requirePrevious = getFieldInteger("Index")!! > 1 && !fields.containsKey("Revoke")

        when (sigLevel) {
            // This doesn't exist in an org entry
            "User-Signature" -> return Result.failure(BadValueException())
            "Custody-Signature" -> {
                // We don't need to do anything else for the custody signature
            }

            "Previous-Hash" -> {
                if (signatures.containsKey("Custody-Signature"))
                    lines.add("Custody-Signature:${signatures["Custody-Signature"]}")
                else {
                    if (requirePrevious)
                        return Result.failure(
                            ComplianceFailureException("Custody-Signature missing")
                        )
                }
            }

            "Hash" -> {
                listOf("Custody-Signature", "Previous-Hash").forEach {
                    if (signatures.containsKey(it))
                        lines.add("$it:${signatures[it]}")
                    else {
                        if (requirePrevious)
                            return Result.failure(ComplianceFailureException("$it missing"))
                    }
                }
            }

            "Organization-Signature" -> {
                listOf("Custody-Signature", "Previous-Hash", "Hash").forEach {
                    if (signatures.containsKey(it))
                        lines.add("$it:${signatures[it]}")
                    else {
                        if (requirePrevious)
                            return Result.failure(ComplianceFailureException("$it missing"))
                    }
                }
            }

            null -> {
                listOf("Custody-Signature", "Previous-Hash", "Hash").forEach {
                    if (signatures.containsKey(it))
                        lines.add("$it:${signatures[it]}")
                    else {
                        if (requirePrevious)
                            return Result.failure(ComplianceFailureException("$it missing"))
                    }
                }
                if (signatures.containsKey("Organization-Signature"))
                    lines.add("Organization-Signature:${signatures["Organization-Signature"]}")
                else
                    return Result.failure(
                        ComplianceFailureException("Organization-Signature missing")
                    )
            }

            else -> return Result.failure(BadValueException())
        }
        lines.add("")
        return Result.success(lines.toString())
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
            return Result.failure(
                ComplianceFailureException("Required field Primary-Verification-Key missing")
            )
        if (!fields.containsKey("Encryption-Key"))
            return Result.failure(
                ComplianceFailureException("Required field Encryption-Key missing")
            )
        if (!signatures.containsKey("Hash"))
            return Result.failure(ComplianceFailureException("Required auth string Hash missing"))

        val outMap = mutableMapOf<String, CryptoString>()
        val outEntry = copy().getOrThrow()


        val signAlgo = CryptoString.fromString(fields["Primary-Verification-Key"]!!.toString())
            ?: return Result.failure(BadFieldValueException("Bad Primary-Verification-Key"))
        // This should *never* have an error. If it does, we have big problems
        val newSPair = SigningPair.generate(signAlgo.prefix).getOrThrow()
        outMap["primary.public"] = newSPair.publicKey
        outMap["primary.private"] = newSPair.privateKey
        outEntry.setField("Primary-Verification-Key", newSPair.publicKey.value)

        val encAlgo =
            CryptoString.fromString(fields["Encryption-Key"]!!.toString()) ?: return Result.failure(
                BadFieldValueException("Bad Encryption-Key")
            )
        val newEPair = EncryptionPair.generate(encAlgo.prefix).getOrThrow()
        outMap["encryption.public"] = newEPair.publicKey
        outMap["encryption.private"] = newEPair.privateKey
        outEntry.setField("Encryption-Key", newEPair.publicKey.value)

        outEntry.setField(
            "Secondary-Verification-Key",
            fields["Primary-Verification-Key"]!!.toString()
        )
        outEntry.addAuthString("Previous-Hash", getAuthString("Hash")!!)

        if (expiration <= 0) setExpires(366)
        else setExpires(expiration)

        var result = outEntry.sign("Custody-Signature", signingPair)
        if (result != null) return Result.failure(result)
        val hashAlgo =
            CryptoString.fromString(signatures["Hash"]!!.toString()) ?: return Result.failure(
                BadFieldValueException("Bad Hash")
            )
        result = outEntry.hash(hashAlgo.prefix)
        if (result != null) return Result.failure(result)
        result = outEntry.sign("Organization-Signature", newSPair)
        if (result != null) return Result.failure(result)

        return Result.success(Pair(outEntry, outMap))
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
        if (previous !is OrgEntry) return Result.failure(TypeCastException())

        val prevIndex = previous.getFieldInteger("Index") ?: return Result.failure(
            MissingDataException("previous Index field missing")
        )
        val currentIndex = getFieldInteger("Index")
            ?: return Result.failure(MissingDataException("Index field missing"))
        if (prevIndex != currentIndex - 1)
            return Result.failure(ComplianceFailureException("Non-sequential entries"))

        val verKeyStr =
            previous.getFieldString("Primary-Verification-Key") ?: return Result.failure(
                MissingDataException("Primary-Verification-Key field missing")
            )
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
        val outEntry = copy().getOrThrow()

        val signAlgo = CryptoString.fromString(fields["Primary-Verification-Key"]!!.toString())
            ?: return Result.failure(BadFieldValueException("Bad Primary-Verification-Key"))
        val newSPair = SigningPair.generate(signAlgo.prefix).getOrThrow()
        outMap["primary.public"] = newSPair.publicKey
        outMap["primary.private"] = newSPair.privateKey
        outEntry.setField("Primary-Verification-Key", newSPair.publicKey.value)

        val encAlgo =
            CryptoString.fromString(fields["Encryption-Key"]!!.toString()) ?: return Result.failure(
                BadFieldValueException("Bad Encryption-Key")
            )
        val newEPair = EncryptionPair.generate(encAlgo.prefix).getOrThrow()
        outMap["encryption.public"] = newSPair.publicKey
        outMap["encryption.private"] = newSPair.privateKey
        outEntry.setField("Encryption-Key", newEPair.publicKey.value)

        if (expiration <= 0) setExpires(366)
        else setExpires(expiration)

        // This new entry has no custody signature--it's a new root entry

        val hash =
            CryptoString.fromString(signatures["Hash"]!!.toString()) ?: return Result.failure(
                BadFieldValueException("Bad Hash")
            )
        outEntry.setField("Revoke", hash.toString())
        var result = outEntry.hash(hash.prefix)
        if (result != null) return Result.failure(result)
        result = outEntry.sign("Organization-Signature", newSPair)
        if (result != null) return Result.failure(result)

        return Result.success(Pair(outEntry, outMap))
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
                return Result.failure(BadValueException())
            }

            val out = OrgEntry()
            for (rawLine in s.split("\r\n")) {
                val line = rawLine.trim()
                if (line.isEmpty()) continue

                val parts = line.split(":", limit = 2)
                if (parts.size != 2) {
                    return Result.failure(BadFieldValueException(line))
                }

                if (parts[1].length > 6144) {
                    return Result.failure(
                        RangeException("Field ${parts[0]} may not be longer than 6144 bytes")
                    )
                }

                val fieldName = parts[0]
                val fieldValue = parts[1]
                when (fieldName) {
                    "Custody-Signature",
                    "Organization-Signature",
                    "Previous-Hash",
                    "Hash" -> {
                        val cs = CryptoString.fromString(fieldValue) ?: return Result.failure(
                            BadFieldValueException(fieldName)
                        )
                        out.addAuthString(fieldName, cs)
                        continue
                    }
                }

                val field = EntryField.fromStrings(fieldName, fieldValue)
                if (field.isFailure) return Result.failure(field.exceptionOrNull()!!)

                val err = out.setField(fieldName, fieldValue)
                if (err != null) return Result.failure(err)
            }

            return out.toSuccess()
        }
    }
}