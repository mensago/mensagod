package libkeycard

import keznacl.CryptoString
import keznacl.toFailure
import keznacl.toSuccess
import java.util.regex.Pattern

/** Data class used for validating field data from raw strings */
sealed class EntryField {

    companion object {
        fun fromStrings(fieldName: String, fieldValue: String): Result<EntryField> {
            return when (fieldName) {
                "Type" -> {
                    val field = StringField.validatedEntryType(fieldValue)
                        ?: return BadFieldValueException(
                            "Entry type must be 'Organization' or 'User', not $fieldValue"
                        ).toFailure()
                    field.toSuccess()
                }

                "Index" -> {
                    val field = IntegerField.fromString(fieldValue)
                        ?: return BadFieldValueException(
                            "Bad $fieldName field value: $fieldValue"
                        ).toFailure()
                    field.toSuccess()
                }

                "Name" -> {
                    val field = StringField.validatedName(fieldValue)
                        ?: return BadFieldValueException(
                            "Bad $fieldName field value: '$fieldValue'"
                        ).toFailure()
                    field.toSuccess()
                }

                "Local-ID" -> {
                    val field = StringField.validatedLocalID(fieldValue)
                        ?: return BadFieldValueException(
                            "Bad $fieldName field value: '$fieldValue'"
                        ).toFailure()
                    field.toSuccess()
                }

                "User-ID" -> {
                    val field = StringField.validatedUserID(fieldValue)
                        ?: return BadFieldValueException(
                            "Bad $fieldName field value: '$fieldValue'"
                        ).toFailure()
                    field.toSuccess()
                }

                "Workspace-ID" -> {
                    val field = StringField.validatedRandomID(fieldValue)
                        ?: return BadFieldValueException(
                            "Bad $fieldName field value: '$fieldValue'"
                        ).toFailure()
                    field.toSuccess()
                }

                "Domain" -> {
                    val field = StringField.validatedDomain(fieldValue)
                        ?: return BadFieldValueException(
                            "Bad $fieldName field value: '$fieldValue'"
                        ).toFailure()
                    field.toSuccess()
                }

                "Contact-Admin",
                "Contact-Abuse",
                "Contact-Support" -> {
                    val field = WAddressField.fromString(fieldValue)
                        ?: return BadFieldValueException(
                            "Bad $fieldName field value: $fieldValue"
                        ).toFailure()
                    field.toSuccess()
                }

                "Contact-Request-Encryption-Key",
                "Contact-Request-Verification-Key",
                "Primary-Verification-Key",
                "Secondary-Verification-Key",
                "Verification-Key",
                "Encryption-Key",
                "Revoke" -> {
                    val field = CryptoStringField.fromString(fieldValue)
                        ?: return BadFieldValueException(
                            "Bad $fieldName field value: $fieldValue"
                        ).toFailure()
                    field.toSuccess()
                }

                "Language" -> {
                    val field = StringField.validatedLanguage(fieldValue)
                        ?: return BadFieldValueException(
                            "Bad $fieldName field value: '$fieldValue'"
                        ).toFailure()
                    field.toSuccess()
                }

                "Time-To-Live" -> {
                    val field = IntegerField.validatedTTL(fieldValue)
                        ?: return BadFieldValueException(
                            "Bad $fieldName field value: '$fieldValue'"
                        ).toFailure()
                    field.toSuccess()
                }

                "Expires" -> {
                    val field = DatestampField.fromString(fieldValue)
                        ?: return BadFieldValueException(
                            "Bad $fieldName field value: $fieldValue"
                        ).toFailure()
                    field.toSuccess()
                }

                "Timestamp" -> {
                    val field = TimestampField.fromString(fieldValue)
                        ?: return BadFieldValueException(
                            "Bad $fieldName field value: $fieldValue"
                        ).toFailure()
                    field.toSuccess()
                }

                else -> BadFieldException(fieldName).toFailure()
            }
        }
    }
}

/** EntryField subclass which represents integers */
class IntegerField(val value: Int) : EntryField() {

    override fun toString(): String {
        return value.toString()
    }

    companion object {

        fun fromString(s: String): IntegerField? {
            return runCatching {
                val i = s.toInt()
                if (i < 1) null else IntegerField(i)
            }.getOrElse { null }
        }

        fun validatedTTL(s: String): IntegerField? {
            val ttl = runCatching { IntegerField(s.toInt()) }.getOrElse { return null }

            return if (ttl.value in 1..30) ttl else null
        }
    }
}

/** EntryField subclass which validates the various string fields for entries */
class StringField(val value: String) : EntryField() {

    override fun toString(): String {
        return value
    }

    companion object {
        private val nameRE = Pattern
            .compile("""^[^\p{C}\s][^\p{C}]{1,61}[^\p{C}\s][^\p{C}]$""")
            .toRegex()
        private val languageRE = Pattern.compile("""^[a-zA-Z]{2,3}(,[a-zA-Z]{2,3})*?$""")
            .toRegex()
        private val controlCharsRE = Pattern.compile("""\p{C}""").toRegex()
        private val randomIDRE = Pattern.compile(
            """^[\da-fA-F]{8}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{12}$"""
        )
            .toRegex()
        private val localIDRE = Pattern.compile("""^([\p{L}\p{M}\p{N}\-_]|\.[^.]){1,64}$""")
            .toRegex()
        private val userIDRE = Pattern.compile("""^([\w\-]|\.[^.]){1,64}$""").toRegex()
        private val domainRE = Pattern.compile("""^([a-zA-Z0-9\-]+)(\.[a-zA-Z0-9\-]+)*$""")
            .toRegex()

        fun validatedEntryType(s: String): StringField? {
            return when (s) {
                "Organization", "User" -> StringField(s)
                else -> null
            }
        }

        fun validatedName(s: String): StringField? {
            if (s.isEmpty() || s.length > 64 ||
                !nameRE.matches(s) ||
                controlCharsRE.matches(s)
            )
                return null
            return StringField(s)
        }

        fun validatedLocalID(s: String): StringField? {
            return if (localIDRE.matches(s)) StringField(s) else null
        }

        fun validatedUserID(s: String): StringField? {
            return if (userIDRE.matches(s)) StringField(s) else null
        }

        fun validatedRandomID(s: String): StringField? {
            return if (randomIDRE.matches(s)) StringField(s) else null
        }

        fun validatedDomain(s: String): StringField? {
            return if (domainRE.matches(s)) StringField(s) else null
        }

        fun validatedLanguage(s: String): StringField? {
            return if (languageRE.matches(s)) StringField(s) else null
        }

    }
}

/** EntryField subclass which houses timestamps */
class TimestampField(val value: Timestamp = Timestamp()) : EntryField() {

    override fun toString(): String {
        return value.toString()
    }

    companion object {

        fun fromString(s: String): TimestampField? {
            val ts = Timestamp.fromString(s)
            return if (ts != null) TimestampField(ts) else null
        }
    }
}

/** DatestampField objects track timestamps which only require date information */
class DatestampField(val value: Timestamp = Timestamp()) : EntryField() {

    override fun toString(): String {
        return value.toDateString()
    }

    companion object {

        fun fromString(s: String): DatestampField? {
            val ts = Timestamp.fromDateString(s)
            return if (ts != null) DatestampField(ts) else null
        }
    }
}

/** EntryField subclass for validating CryptoString data */
class CryptoStringField(val value: CryptoString) : EntryField() {

    override fun toString(): String {
        return value.toString()
    }

    companion object {

        fun fromString(s: String): CryptoStringField? {
            val cs = CryptoString.fromString(s)
            return if (cs != null) CryptoStringField(cs) else null
        }
    }
}

/** EntryField subclass which holds workspace addresses */
class WAddressField(val value: WAddress) : EntryField() {

    override fun toString(): String {
        return value.toString()
    }

    companion object {

        fun fromString(s: String): WAddressField? {
            val w = WAddress.fromString(s)
            return if (w != null) WAddressField(w) else null
        }
    }
}