package libmensago

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

    val schema = SchemaBuilder {
        Field { "Workspace-ID", Field.RandomID, true },
        Field { "User-ID", Field.UserID, false },
    }
    schema.validate(state.message.data)
        ?.let { it.sendCatching("Failed to send validation failure message") }
    val wid = schema.getRandomID("Workspace-ID")

*/
