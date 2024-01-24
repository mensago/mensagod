package mensagod.commands

import mensagod.ClientSession

/**
 * Calls the appropriate command handler based on the session's current state.
 *
 * @throws java.io.IOException For network errors
 */
fun processCommand(state: ClientSession) {
    when (state.message.action) {
        "GETWID" -> commandGetWID(state)
        "PREREG" -> commandPreregister(state)
        "REGCODE" -> commandRegCode(state)
        else -> commandUnrecognized(state)
    }
}
