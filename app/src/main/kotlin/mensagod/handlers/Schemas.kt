package mensagod.handlers

import libmensago.MsgField
import libmensago.MsgFieldType
import libmensago.Schema

/**
 * The Schemas singleton just contains instances of all the client request schemas used by the
 * Mensago protocol.
 */
object Schemas {

    val getWID = Schema(
        MsgField("User-ID", MsgFieldType.UserID, true),
        MsgField("Domain", MsgFieldType.Domain, false)
    )
}
