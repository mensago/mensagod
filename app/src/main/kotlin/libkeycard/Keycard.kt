package libkeycard

import keznacl.*
import java.util.*

/**
 * The Keycard class represents the chain of custody which binds key material to an identity on the
 * Mensago platform. The most common tasks performed with this class are validating keycards for
 * message recipients and creating a new entry for a person's keycard prior to uploading to the
 * account's managing server. Note that creating a new, empty Keycard instance is done by calling
 * Keycard.new()
 */
class Keycard private constructor(
    cardType: String,
    val entries: MutableList<Entry> = mutableListOf()
) {
    var entryType = cardType
        private set

    val current: Entry?
        get() {
            return entries.lastOrNull()
        }

    /** Returns the entry matching the hash passed to it */
    fun findByHash(hash: Hash): Entry? {
        val hashstr = hash.toString()
        return entries.find {
            it.hasAuthString("Hash") && it.getAuthString("Hash").toString() == hashstr
        }
    }

    /** Convenience function which calls getOwner() on the current entry in the card */
    fun getOwner(): String? {
        return if (entries.isEmpty()) null
        else entries.last().getOwner()
    }

    /**
     * Creates a new Entry object in the keycard. Organization keycards are complete and compliant
     * when chain() returns. User keycards will require crossSign() and userSign() to be called
     * before the new entry is compliant.
     *
     * This method returns a Map which contains the newly-generated keys associated with the
     * new keycard entry. The fields returned will depend on the keycard type.
     *
     * Organization keycards will return the fields `primary.public`, `primary.private`,
     * `encryption.public`, and `encryption.private`. The secondary signing keypair is not returned
     * because the signing pair passed to the method becomes the secondary signing keypair when
     * this call completes.
     *
     * User keycards will return the fields `crsigning.public`, `crsigning.private`,
     * `crencryption.public`, `crencryption.private`, `signing.public`, `signing.private`,
     * `encryption.public`, and `encryption.private`.
     */
    fun chain(signingPair: SigningPair, expires: Int = -1): Result<Map<String, CryptoString>> {
        if (entries.isEmpty()) return EmptyDataException().toFailure()

        val current = entries.last()
        val (newEntry, keys) = current.chain(signingPair, expires)
            .getOrElse { return it.toFailure() }
        entries.add(newEntry)

        return keys.toSuccess()
    }

    /**
     * This convenience method applies only to user keycards and is used to set the organization's
     * signature for the current entry.
     */
    fun crossSign(signingPair: SigningPair): Throwable? {
        if (entries.isEmpty()) return EmptyDataException()

        return entries.last().sign("Organization-Signature", signingPair)
    }

    /**
     * This convenience method applies only to user keycards and is used to generate the hash for
     * the current entry and add the final user signature. Once this has been applied, the current
     * entry for the keycard should be compliant and pass verification.
     */
    fun userSign(hashAlgorithm: CryptoType, signingPair: SigningPair): Throwable? {
        if (entries.isEmpty()) return EmptyDataException()

        val current = entries.last()

        current.hash(hashAlgorithm).let { if (it != null) return it }
        return current.sign("User-Signature", signingPair)
    }

    /** Verifies the keycard's complete chain of custody. */
    fun verify(): Result<Boolean> {
        if (entries.isEmpty()) return EmptyDataException().toFailure()

        for (i in 0 until entries.size - 1) {
            entries[i].isCompliant().let {
                if (it != null)
                    return it.toFailure()
            }
            val result = entries[i + 1].verifyChain(entries[i])
            if (result.isFailure) return result
            if (!result.getOrNull()!!) return false.toSuccess()
        }

        return true.toSuccess()
    }

    /** Returns the entired keycard as a string */
    override fun toString(): String {
        val sj = StringJoiner("")
        entries.forEach {
            sj.add(
                "----- BEGIN ENTRY -----\r\n" +
                        it.getFullText(null) +
                        "----- END ENTRY -----\r\n"
            )
        }
        return sj.toString()
    }

    companion object {

        /** Creates a new, empty keycard. */
        fun new(cardType: String): Keycard? {
            return when (cardType) {
                "User", "Organization" -> Keycard(cardType)
                else -> null
            }
        }

        /** Instantiates a keycard instance from text which contains one or more entries */
        fun fromString(data: String): Result<Keycard> {
            if (data.isEmpty()) return EmptyDataException().toFailure()

            val entries = parseEntries(data).getOrElse { return it.toFailure() }
            if (entries.isEmpty()) return EmptyDataException().toFailure()

            val cardType = entries[0].getFieldString("Type")
                ?: return BadFieldException("Keycard missing Type field").toFailure()

            return Keycard(cardType, entries).toSuccess()
        }

        private fun parseEntries(data: String): Result<MutableList<Entry>> {
            val out = mutableListOf<Entry>()
            var cardType = ""
            var accumulator = StringJoiner("\r\n")

            val rawLines = data.split("\r\n")

            for (i in rawLines.indices) {
                val trimmed = rawLines[i].trim()
                if (trimmed.isEmpty()) continue

                when (trimmed) {
                    "----- BEGIN ENTRY -----" -> {
                        accumulator = StringJoiner("\r\n")
                        continue
                    }

                    "----- END ENTRY -----" -> {
                        val entry: Entry = when (cardType) {
                            "User" -> UserEntry.fromString(accumulator.toString())
                            "Organization" -> OrgEntry.fromString(accumulator.toString())
                            else -> return Result.failure(InvalidKeycardException())
                        }.getOrElse { return it.toFailure() }

                        out.add(entry)
                        continue
                    }
                }

                val parts = trimmed.split(":", limit = 2)
                if (parts.size != 2)
                    return BadFieldException("Invalid line $i: $trimmed").toFailure()

                val fieldName = parts[0]

                if (fieldName == "Type") {
                    if (cardType.isEmpty()) {
                        cardType = parts[1]
                    } else {
                        if (cardType != parts[1]) {
                            return BadFieldValueException("Entry type must match keycard type")
                                .toFailure()
                        }
                    }
                }

                accumulator.add(trimmed)
            }

            return out.toSuccess()
        }
    }
}