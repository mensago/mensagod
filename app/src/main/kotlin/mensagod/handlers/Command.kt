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
        "CANCEL" -> commandCancel(state)
        "COPY" -> commandCopy(state)
        "DELETE" -> commandDelete(state)
        "DEVICE" -> commandDevice(state)
        "DEVKEY" -> commandDevKey(state)
        "DOWNLOAD" -> commandDownload(state)
        "EXISTS" -> commandExists(state)
        "GETCARD" -> commandGetCard(state)
        "GETDEVICEINFO" -> commandGetDeviceInfo(state)
        "GETQUOTAINFO" -> commandGetQuotaInfo(state)
        "GETUPDATES" -> commandGetUpdates(state)
        "GETWID" -> commandGetWID(state)
        "IDLE" -> commandIdle(state)
        "ISCURRENT" -> commandIsCurrent(state)
        "KEYPKG" -> commandKeyPkg(state)
        "LIST" -> commandList(state)
        "LISTDIRS" -> commandListDirs(state)
        "LOGIN" -> commandLogin(state)
        "LOGOUT" -> commandLogout(state)
        "MKDIR" -> commandMkDir(state)
        "MOVE" -> commandMove(state)
        // "ORGREVOKE" -> commandOrgRevoke(state)
        "PASSCODE" -> commandPassCode(state)
        "PASSWORD" -> commandPassword(state)
        "PREREG" -> commandPreregister(state)
        "REGCODE" -> commandRegCode(state)
        "REGISTER" -> commandRegister(state)
        // "REMOVEDEVICE" -> command(state)
        // "RESETPASSWORD" -> command(state)
        // "REVOKE" -> commandRevoke(state)
        // "RMDIR" -> command(state)
        // "SELECT" -> command(state)
        "SEND" -> commandSend(state)
        // "SENDLARGE" -> command(state)
        // "SETDEVICEINFO" -> command(state)
        // "SETPASSWORD" -> command(state)
        // "SETQUOTA" -> command(state)
        // "SETSTATUS" -> command(state)
        // "UNREGISTER" -> command(state)
        "UPLOAD" -> commandUpload(state)
        else -> commandUnrecognized(state)
    }
}
