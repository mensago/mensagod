package libkeycard

import keznacl.*
import java.time.Instant

/**
 * The Entry class represents a portion of a keycard. Its primary job is to implement functionality
 * common to its child classes, OrgEntry and UserEntry.
 */
sealed class Entry {
    protected val fields = mutableMapOf<String, EntryField>()
    protected val signatures = mutableMapOf<String, CryptoString>()

    fun getField(fieldName: String): EntryField? {
        return fields[fieldName]
    }

    fun hasField(fieldName: String): Boolean {
        return fields.containsKey(fieldName)
    }

    /**
     * Sets the value of one of the fields in an entry. The internal representation of each of the
     * fields checks formatting and validity of the data passed to the call. Calling this method
     * when an entry already has an existing field of the same name will cause the value for the
     * field to be updated.
     */
    fun setField(fieldName: String, fieldValue: String): Throwable? {
        if (!isFieldAllowed(fieldName)) {
            return BadFieldException("$fieldName not allowed")
        }

        val result = EntryField.fromStrings(fieldName, fieldValue)
        if (result.isFailure) return result.exceptionOrNull()!!
        fields[fieldName] = result.getOrNull()!!

        return null
    }

    fun deleteField(fieldName: String) {
        fields.remove(fieldName)
    }

    // Type-specific field methods for the most common/annoying types

    /** Convenience method to reduce the number of casts needed when setting integer field values */
    fun setFieldInteger(fieldName: String, value: Int) {
        fields[fieldName] = IntegerField(value)
    }

    /** Convenience method to reduce the number of casts needed when getting field values */
    fun getFieldInteger(fieldName: String): Int? {
        val field = fields[fieldName] ?: return null
        return if (field is IntegerField) field.value else null
    }

    /** Convenience method to reduce the number of casts needed when getting field values */
    fun getFieldString(fieldName: String): String? {
        val field = fields[fieldName] ?: return null
        return field.toString()
    }

    /** Obtains the requested encryption key from the entry, if it exists */
    fun getEncryptionKey(fieldName: String): EncryptionKey? {
        val field = fields[fieldName] ?: return null
        return EncryptionKey.fromString(field.toString()).getOrNull()
    }

    /** Obtains the requested hash from the entry, if it exists */
    fun getHash(fieldName: String): Hash? {
        val field = signatures[fieldName] ?: return null
        return Hash.fromString(field.toString())
    }

    /** Obtains the requested verification key from the entry, if it exists */
    fun getVerificationKey(fieldName: String): VerificationKey? {
        val field = fields[fieldName] ?: return null
        return VerificationKey.fromString(field.toString()).getOrNull()
    }

    /**
     * Returns the owner for the entry, which will be a string containing a workspace address, if the entry is for a
     * user, or a domain in the case of organizations. It will return null if the required fields are not populated
     * (Domain, Domain + Workspace-ID)
     */
    abstract fun getOwner(): String?

    /**
     * Checks the formatting of the regular fields in the entry and returns false if a field is missing or does not
     * comply with the spec. This method is usually called to ensure that the data in an entry is valid before
     * proceeding with the signing and hashing process.
     */
    abstract fun isDataCompliant(): Throwable?

    /**
     * Returns a Throwable if the entry has any compliance issues, including missing or bad hashes and/or signatures.
     * This method performs all the checks made in `isDataCompliant()` and more. Note that only the format of signatures
     * and hashes are checked. The validity of a hash or signature must be checked using `verify()` or `verify_chain()`.
     *
     * For the specific requirements of an entry, please consult the documentation for that entry class' isCompliant()
     * implementation.
     */
    abstract fun isCompliant(): Throwable?

    /**
     * Sets the expiration date for the entry. Note that this call isn't generally necessary as the child classes
     * typically set the recommended value for their type. As per the spec, the expiration time may not be greater than
     * 1095 days -- roughly 3 years -- or less than 1 day. A value less than 7 is not recommended.
     */
    fun setExpires(days: Int) {
        val actualDays = when {
            days > 1095 -> 1095
            days < 1 -> 1
            else -> days
        }
        fields["Expires"] = DatestampField(Timestamp.plusDays(actualDays))
    }

    /**
     * Returns true if the entry has exceeded its expiration date or an error if an unexpected error occurred.
     */
    fun isExpired(): Result<Boolean> {
        val baseField = fields["Expires"] ?: return Result.failure(MissingDataException())
        if (baseField !is DatestampField) return Result.failure(BadFieldException())
        val expires = baseField.value
        return Result.success(expires.value.isBefore(Instant.now()))
    }

    /** Returns the body text of the entry */
    abstract fun getText(): String

    /**
     * Returns the full text of the entry, up to but not including the one specified. Passing a null string will result
     * in the entire entry being returned.
     *
     * The order for organization entries:
     *
     * - Custody-Signature
     * - Previous-Hash
     * - Hash
     * - Organization-Signature
     *
     * The order for user entries:
     *
     * - Custody-Signature
     * - Organization-Signature
     * - Previous-Hash
     * - Hash
     * - User-Signature
     */
    abstract fun getFullText(sigLevel: String?): Result<String>

    /**
     * Sets the specified authentication string to the value passed. NOTE: no validation of the string is performed by
     * this call. The primary use for this method is to set the Previous-Hash for the entry.
     */
    fun addAuthString(astype: String, value: CryptoString): Throwable? {
        val validAuthStrings = listOf(
            "Custody-Signature", "Organization-Signature", "Previous-Hash", "Hash",
            "User-Signature"
        )
        if (astype !in validAuthStrings) return BadFieldException()

        signatures[astype] = value
        return null
    }

    /** Returns true if the entry has the requested auth string (signature, hash, etc.) */
    fun hasAuthString(astype: String): Boolean {
        return signatures.containsKey(astype)
    }

    /** Returns the requested auth string (signature, hash, etc) or null if not found. */
    fun getAuthString(astype: String): CryptoString? {
        return signatures[astype]
    }

    /** Deletes the requested auth string. */
    fun deleteAuthString(astype: String) {
        fields.remove(astype)
    }

    /**
     * Creates the requested signature. Requirements for this call vary with the entry type implementation; see child
     * class documentation for specific details. OutOfOrderSignature is returned if other required authentication
     * strings are missing when signing is requested. EntryTypeException is returned if the entry does not support the
     * type of signature requested.
     */
    fun sign(astype: String, signingPair: SigningPair): Throwable? {
        val totalData = getFullText(astype).getOrElse { return it }
        val signature = signingPair.sign(totalData.toByteArray()).getOrElse { return it }
        addAuthString(astype, signature)

        return null
    }


    /**
     * Verifies the requested signature. BadValueException is returned for a signature type not used by the specific
     * implementation. A boolean value is returned if the signature verifies (or not) and an error if something else
     * happened which prevented verification from occurring.
     */
    fun verifySignature(astype: String, key: Verifier): Result<Boolean> {
        val signature = getAuthString(astype) ?: return Result.failure(BadValueException())
        val totalData = getFullText(astype).getOrElse { return it.toFailure() }
        return key.verify(totalData.toByteArray(), signature)
    }

    /**
     * Calculates the hash for the entry text using the specified algorithm. For information on signature/hash order,
     * please see the documentation for `getFullText()` for the corresponding type of entry. OutOfOrderSignature is
     * returned if other required authentication strings are missing when hashing is requested.
     */
    fun hash(algorithm: CryptoType = getPreferredHashAlgorithm()): Throwable? {
        val totalData = getFullText("Hash").getOrElse { return it }

        val hashValue = hash(totalData.toByteArray(), algorithm)
        if (hashValue.isFailure) return hashValue.exceptionOrNull()!!

        addAuthString("Hash", hashValue.getOrNull()!!)

        return null
    }

    /**
     * Verifies the data of the entry with the hash currently assigned. Returns true/false on
     * success/mismatch and an error if something went wrong which prevented the hash comparison.
     *
     * @exception MissingDataException Returned if the entry is missing its hash
     * @exception BadFieldValueException Returned if the stored hash is unsupported or invalid
     */
    fun verifyHash(): Result<Boolean> {
        val hashCS = getAuthString("Hash") ?: return MissingDataException().toFailure()
        val currentHash = hashCS.toHash() ?: return BadFieldValueException().toFailure()

        val totalData = getFullText("Hash").getOrElse { return it.toFailure() }
        return currentHash.check(totalData.encodeToByteArray())
    }

    /**
     * Creates a new Entry object with new keys and a custody signature. It requires the signing keypair used for the
     * entry so that the Custody-Signature field is generated correctly. An expiration period for the new entry may be
     * specified. If the default expiration value is used, the default for the entry type is used.
     */
    abstract fun chain(
        signingPair: SigningPair,
        expiration: Int = 0
    ): Result<Pair<Entry, Map<String, CryptoString>>>

    /**
     * Verifies the chain of custody between the current Entry instance and the provided entry. Specific conditions for
     * verification are provide in the documentation for their corresponding implementation.
     */
    abstract fun verifyChain(previous: Entry): Result<Boolean>

    /**
     * This method is called when the current entry must be revoked because one or more keys were compromised. A new
     * root entry is created with a `Revoke` field containing the hash of the current one and an `Index` which is,
     * like `chain()`, one greater than the current entry.
     */
    abstract fun revoke(expiration: Int = 0): Result<Pair<Entry, Map<String, CryptoString>>>

    /** Returns true if the previous entry in the keycard was revoked */
    fun isRevoked(): Boolean {
        return fields.containsKey("Revoke")
    }

    fun copy(): Result<Entry> {
        val entryType: StringField =
            fields["Type"] as StringField? ?: return Result.failure(BadFieldException())
        val out = when (entryType.value) {
            "User" -> UserEntry()
            "Organization" -> OrgEntry()
            else -> return Result.failure(BadFieldValueException())
        }

        for (f in fields) {
            when (f.key) {
                "Index",
                "PrimaryVerificationKey",
                "SecondaryVerificationKey",
                "EncryptionKey",
                "Expires",
                "Timestamp",
                -> { /* Field is set correctly in new(). Do nothing. */
                }

                else -> {
                    val result = out.setField(f.key, f.value.toString())
                    if (result != null) return Result.failure(result)
                }
            }
        }
        val newIndex = (fields["Index"] as IntegerField).value + 1
        out.fields["Index"] = IntegerField(newIndex)

        return out.toSuccess()
    }

    /**
     * Internal method required by subclasses which returns true if the field is one of those permitted for the entry
     * type.
     */
    protected abstract fun isFieldAllowed(fieldName: String): Boolean
}
