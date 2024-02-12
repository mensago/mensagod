package mensagod

import libkeycard.Domain
import libkeycard.RandomID

/** Max number of network errors before we close the connection */
const val gMaxNetworkErrors = 10

/** A generator of registration passphrases */
val gRegCodeGenerator = RegCodeGenerator()

// This is used so much that it only makes sense to have a global variable for it. It is
// set in only one place, but has to be set at runtime, so we use a temporary value to start with
// so that we don't have to constantly deal with nullability on top of it.
/** The server's default domain. */
var gServerDomain = Domain.fromString("localdomain.priv")!!

val gServerDevID = RandomID.fromString("00000000-0000-0000-0000-000000000000")!!
