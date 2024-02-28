package mensagod.handlers

import mensagod.ClientSession

/**
 * Calls the appropriate command handler based on the session's current state.
 *
 * @throws java.io.IOException For network errors
 */
fun processCommand(state: ClientSession) {

    state.checkForUpdates()
    when (state.message.action) {
        "ADDENTRY" -> commandAddEntry(state)
        "DEVICE" -> commandDevice(state)
        "DOWNLOAD" -> commandDownload(state)
        "GETCARD" -> commandGetCard(state)
        "GETWID" -> commandGetWID(state)
        "KEYPKG" -> commandKeyPkg(state)
        "ISCURRENT" -> commandIsCurrent(state)
        "LOGIN" -> commandLogin(state)
        "LOGOUT" -> commandLogout(state)
        "PASSWORD" -> commandPassword(state)
        "PREREG" -> commandPreregister(state)
        "REGCODE" -> commandRegCode(state)
        "UPLOAD" -> commandUpload(state)
        else -> commandUnrecognized(state)
    }
}