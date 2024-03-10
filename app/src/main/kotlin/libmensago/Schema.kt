package libmensago

import keznacl.CryptoString
import keznacl.Hash
import libkeycard.*

/**
 * Enum class for denoting MsgField types during Schema validation
 *
 * @see MsgField
 * @see Schema
 */
enum class MsgFieldType {
    CryptoString,
    Domain,
    Hash,
    Integer,
    MAddress,
    Path,
    RandomID,
    String,
    UnixTime,
    UserID,
}

/**
 * The MsgField type contains validation information about a message field.
 *
 * @see Schema
 */
data class MsgField(val name: String, val type: MsgFieldType, val req: Boolean)

/**
 * The Schema class is used for validating attached message data and converting it to the desired
 * data types.
 *
 * @return True on success and null on failure.
 * @see MsgField
 * @see MsgFieldType
 */
class Schema(vararg args: MsgField) {
    val fields = args.associateBy { it.name }

    /**
     * Validates the data map passed to it and executes the handler code if validation should fail
     *
     * @return True if the data map passes validation and null if not. False is never returned.
     */
    fun validate(data: Map<String, String>, failHandler: (String, Throwable) -> Unit): Boolean? {
        for (field in fields.values) {

            if (!data.containsKey(field.name)) {
                if (field.req) {
                    val out = MissingFieldException()
                    failHandler(field.name, out)
                    return null
                }
                continue
            }

            val isValid = when (field.type) {
                MsgFieldType.CryptoString, MsgFieldType.Hash ->
                    CryptoString.checkFormat(data[field.name]!!)

                MsgFieldType.Domain -> Domain.checkFormat(data[field.name]!!)
                MsgFieldType.Integer -> {
                    val result = runCatching { data[field.name]!!.toInt() }
                    if (result.isSuccess)
                        result.getOrNull()!! >= 0
                    else
                        false
                }

                MsgFieldType.MAddress -> MAddress.checkFormat(data[field.name]!!)
                MsgFieldType.Path -> MServerPath.checkFormat(data[field.name]!!)
                MsgFieldType.RandomID -> RandomID.checkFormat(data[field.name]!!)
                MsgFieldType.String -> data[field.name]!!.isNotEmpty()
                MsgFieldType.UnixTime -> {
                    val result = runCatching { data[field.name]!!.toLong() }
                    if (result.isSuccess)
                        result.getOrNull()!! >= 0
                    else
                        false
                }

                MsgFieldType.UserID -> UserID.checkFormat(data[field.name]!!)
            }

            if (!isValid) {
                val out = BadFieldValueException()
                failHandler(field.name, out)
                return null
            }
        }
        return true
    }

    /**
     * Returns the requested field as a CryptoString or null if (a) the field isn't in the schema or
     * (b) the field's data is invalid or isn't present in the case of optional fields.
     */
    fun getCryptoString(field: String, data: Map<String, String>): CryptoString? {
        if (field !in fields.keys || field !in data.keys) return null
        return CryptoString.fromString(data[field]!!)
    }

    /**
     * Returns the requested field as a Domain or null if (a) the field isn't in the schema or
     * (b) the field's data is invalid or isn't present in the case of optional fields.
     */
    fun getDomain(field: String, data: Map<String, String>): Domain? {
        if (field !in fields.keys) return null
        return Domain.fromString(data[field])
    }

    /**
     * Returns the requested field as a Hash or null if (a) the field isn't in the schema or
     * (b) the field's data is invalid or isn't present in the case of optional fields.
     */
    fun getHash(field: String, data: Map<String, String>): CryptoString? {
        if (field !in fields.keys || field !in data.keys) return null
        return Hash.fromString(data[field]!!)
    }

    /**
     * Returns the requested field as an Int or null if (a) the field isn't in the schema or
     * (b) the field's data is invalid or isn't present in the case of optional fields. Because the
     * API does not deal in negative values, integers returned by this call are non-negative, but
     * the call does not return UInt for compatibility reasons -- Int is used everywhere in the
     * Java API. :(
     */
    fun getInteger(field: String, data: Map<String, String>): Int? {
        if (field !in fields.keys || field !in data.keys) return null
        return try {
            val out = data[field]!!.toInt()
            if (out >= 0) out else null
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Returns the requested field as a MAddress or null if (a) the field isn't in the schema or
     * (b) the field's data is invalid or isn't present in the case of optional fields.
     */
    fun getMAddress(field: String, data: Map<String, String>): MAddress? {
        if (field !in fields.keys) return null
        return MAddress.fromString(data[field])
    }

    /**
     * Returns the requested field as an MServerPath or null if (a) the field isn't in the schema or
     * (b) the field's data is invalid or isn't present in the case of optional fields.
     */
    fun getPath(field: String, data: Map<String, String>): MServerPath? {
        if (field !in fields.keys || field !in data.keys) return null
        return MServerPath.fromString(data[field]!!)
    }

    /**
     * Returns the requested field as a RandomID or null if (a) the field isn't in the schema or
     * (b) the field's data is invalid or isn't present in the case of optional fields.
     */
    fun getRandomID(field: String, data: Map<String, String>): RandomID? {
        if (field !in fields.keys) return null
        return RandomID.fromString(data[field])
    }

    /**
     * Returns the requested field as a String or null if (a) the field isn't in the schema or
     * (b) the field's data is empty or isn't present in the case of optional fields.
     */
    fun getString(field: String, data: Map<String, String>): String? {
        if (field !in fields.keys || field !in data.keys) return null
        return data[field]!!.ifEmpty { null }
    }

    /**
     * Returns the requested field as an Int or null if (a) the field isn't in the schema or
     * (b) the field's data is invalid or isn't present in the case of optional fields.
     */
    fun getUnixTime(field: String, data: Map<String, String>): Long? {
        if (field !in fields.keys || field !in data.keys) return null
        return try {
            data[field]!!.toLong()
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Returns the requested field as a UserID or null if (a) the field isn't in the schema or
     * (b) the field's data is invalid or isn't present in the case of optional fields.
     */
    fun getUserID(field: String, data: Map<String, String>): UserID? {
        if (field !in fields.keys) return null
        return UserID.fromString(data[field])
    }
}
