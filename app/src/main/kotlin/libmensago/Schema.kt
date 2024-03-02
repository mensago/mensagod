package libmensago

import keznacl.CryptoString
import libkeycard.Domain
import libkeycard.MissingFieldException
import libkeycard.RandomID
import libkeycard.UserID

/*
    Message validation:
    Check that all required fields exist
    Validate values for required fields
    Check if optional fields exist and validate if they do

    Types of data in requests:
    Unix time (Long) / >= 0
    Domain / meets format
    UserID / meets format
    RandomID / meets format
    General string / is non-empty
    CryptoString / meets format
    MPath / meets format
    Timestamp? / meets format
    Integer / >= 0

    This kind of stuff applies to both server responses and client request and only concerns the
    attached data. Essentially we're checking the attachment schema and validating and returning
    all data

    Schema Entry Components: Field name, field type, required
    Checking all fields existence requires all schema entries
    The ClientSession get* methods already do some of this

    The ideal way of writing this would be:

    val schema = SchemaBuilder(
        Field("Workspace-ID", Field.RandomID, true),
        Field("User-ID", Field.UserID, false),
    )
    schema.validate(state.message.data)
        ?.let { QuickResponse.sendBadRequest("Failed to send validation failure message") }
    val wid = schema.getRandomID("Workspace-ID")

*/

enum class MsgFieldType {
    CryptoString,
    Domain,
    Integer,
    Path,
    RandomID,
    String,
    UnixTime,
    UserID,
}

/** The MsgField type contains validation information about a message field. */
data class MsgField(val name: String, val type: MsgFieldType, val req: Boolean)

/**
 * The Schema class is used for validating attached message data and converting it to the desired
 * data types.
 */
class Schema(vararg args: MsgField) {
    val fields = args.associateBy { it.name }

    /**
     * Validates the data map passed to it and executes the handler code if validation should fail
     */
    fun validate(data: Map<String, String>, failHandler: (String, Throwable) -> Unit) {
        for (field in fields.values) {

            if (!data.containsKey(field.name)) {
                if (field.req) {
                    failHandler(field.name, MissingFieldException())
                    return
                }
                continue
            }

            val isValid = when (field.type) {
                MsgFieldType.CryptoString -> CryptoString.checkFormat(data[field.name]!!)
                MsgFieldType.Domain -> Domain.checkFormat(data[field.name]!!)
                MsgFieldType.Integer -> {
                    val result = runCatching { data[field.name]!!.toInt() }
                    if (result.isSuccess)
                        result.getOrNull()!! >= 0
                    else
                        false
                }

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
        }
    }
}
