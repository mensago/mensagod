package mensagod

import libkeycard.Domain
import libkeycard.RandomID
import libkeycard.WAddress

/** Max number of network errors before we close the connection */
const val gMaxNetworkErrors = 10

/** The server's default domain. */
var gServerDomain = Domain.fromString("localdomain.priv")!!

/** The server's workspace ID / device ID */
val gServerDevID = RandomID.fromString("00000000-0000-0000-0000-000000000000")!!

/**  A workspace address to represent the server */
var gServerAddress = WAddress.fromParts(gServerDevID, gServerDomain)


