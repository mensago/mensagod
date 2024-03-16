package mensagod.handlers

import keznacl.*
import libkeycard.*
import libmensago.MServerPath
import libmensago.ResourceExistsException
import libmensago.ServerException
import libmensago.ServerResponse
import mensagod.*
import mensagod.auth.AuthAction
import mensagod.auth.ServerTarget
import mensagod.auth.WIDActor
import mensagod.auth.WorkspaceTarget
import mensagod.dbcmds.*
import java.net.InetAddress

// ARCHIVE(Password-Hash, Workspace-ID=null)
fun commandArchive(state: ClientSession) {
    val schema = Schemas.archive
    if (!state.requireLogin(schema)) return

    val passHash = schema.getString("Password-Hash", state.message.data)!!
    if (passHash.codePoints().count() !in 16..128) {
        state.quickResponse(400, "BAD REQUEST", "Invalid password hash")
        return
    }

    checkPassword(DBConn(), state.wid!!, passHash).getOrElse {
        state.internalError(
            "commandArchive: error checking password: $it",
            "error checking password"
        )
        return
    }.onFalse {
        state.quickResponse(401, "UNAUTHORIZED")
        return
    }

    val targetWID = schema.getRandomID("Workspace-ID", state.message.data)
    if (targetWID != null) {
        val target = WorkspaceTarget.fromWID((targetWID)).getOrElse {
            state.internalError(
                "commandArchive: error checking workspace status: $it",
                "error checking workspace status"
            )
            return
        } ?: run {
            state.quickResponse(404, "NOT FOUND")
            return
        }

        target.isAuthorized(WIDActor(state.wid!!), AuthAction.Archive)
            .getOrElse {
                state.internalError(
                    "commandArchive.checkAuth exception: $it",
                    "authorization check error"
                )
                return
            }.onFalse {
                state.quickResponse(403, "FORBIDDEN")
                return
            }
    }

    val db = DBConn()
    // The support and abuse built-in accounts can't be deleted
    listOf("support", "abuse").forEach {
        val builtinWID = resolveUserID(db, UserID.fromString(it)!!).getOrElse {
            state.quickResponse(300, "INTERNAL SERVER ERROR", "user ID lookup error")
            return
        }
        if (state.wid!! == builtinWID) {
            state.quickResponse(
                403, "FORBIDDEN",
                "Can't archive the built-in $it account"
            )
            return
        }
    }

    // Admin mode
    if (targetWID != null) {
        archiveWorkspace(db, targetWID)?.let {
            state.internalError(
                "commandArchive: error archiving workspace: $it",
                "error archiving workspace"
            )
            return
        }
        state.quickResponse(200, "OK")
    }

    archiveWorkspace(db, state.wid!!)?.let {
        state.internalError(
            "commandArchive: error archiving workspace: $it",
            "error archiving workspace"
        )
        return
    }
    state.loginState = LoginState.NoSession
    state.quickResponse(202, "ARCHIVED")
}

// PREREG(User-ID="", Workspace-ID="",Domain="")
fun commandPreregister(state: ClientSession) {

    val schema = Schemas.preregister
    if (!state.requireLogin(schema)) return

    ServerTarget().isAuthorized(WIDActor(state.wid!!), AuthAction.Preregister)
        .getOrElse {
            state.internalError(
                "commandPreregister.checkAuth exception: $it",
                "authorization check error"
            )
            return
        }.onFalse {
            state.quickResponse(
                403, "FORBIDDEN",
                "Only admins can preregister accounts"
            )
            return
        }

    val uid = schema.getUserID("User-ID", state.message.data)
    val wid = schema.getRandomID("Workspace-ID", state.message.data)
    val domain = schema.getDomain("Domain", state.message.data)

    val db = DBConn()
    val outUID = if (uid != null) {
        resolveUserID(db, uid).getOrElse {
            state.internalError(
                "commandPreregister.resolveUserID exception: $it",
                "uid lookup error"
            )
            return
        }?.let {
            ServerResponse(408, "RESOURCE EXISTS", "user ID exists")
                .sendCatching(
                    state.conn,
                    "commandPreregister.resolveUserID exists send error"
                )
            return
        }
        uid
    } else null

    val outWID = if (wid != null) {
        checkWorkspace(db, wid).getOrElse {
            state.internalError(
                "commandPreregister.checkWorkspace exception: $it",
                "wid lookup error"
            )
            return
        }?.let {
            runCatching {
                ServerResponse(408, "RESOURCE EXISTS", "workspace ID exists")
                    .send(state.conn)
            }.getOrElse {
                logDebug("commandPreregister.checkWorkspace exists send error: $it")
            }
            return
        }
        wid
    } else {
        var newWID: RandomID?
        do {
            newWID = runCatching {
                val tempWID = RandomID.generate()
                val status = checkWorkspace(db, tempWID).getOrElse {
                    state.internalError(
                        "commandPreregister.checkWorkspace(newWID) exception: $it",
                        "new wid lookup error"
                    )
                    return
                }
                if (status == null)
                    tempWID
                else
                    null
            }.getOrElse {
                state.internalError(
                    "commandPreregister.checkWorkspace exception: $it",
                    "wid lookup error"
                )
                return
            }
        } while (newWID == null)
        newWID
    }

    val outDom = domain ?: gServerDomain

    // Now that we've gone through the pain of covering for missing arguments and validating the
    // ones that actually exist, preregister the account.
    val regcode = RegCodeGenerator.getPassphrase(
        ServerConfig.get().getInteger("security.diceware_wordcount")!!
    )
    val reghash = Argon2idPassword().updateHash(regcode).getOrElse {
        state.internalError(
            "commandPreregister.hashRegCode exception: $it",
            "registration code hashing error"
        )
        return
    }

    preregWorkspace(db, outWID, outUID, outDom, reghash)?.let {
        if (it is ResourceExistsException) {
            ServerResponse(408, "RESOURCE EXISTS")
                .sendCatching(state.conn, "commandPreregister error sending resource exists")
            return
        }
        state.internalError(
            "commandPreregister.preregWorkspace exception: $it",
            "preregistration error"
        )
        return
    }

    val lfs = LocalFS.get()
    val handle = lfs.entry(MServerPath("/ wsp $outWID"))
    handle.makeDirectory()?.let {
        state.internalError(
            "commandPreregister.makeWorkspace exception: $it",
            "preregistration workspace creation failure"
        )
        return
    }

    val resp = ServerResponse(200, "OK")
    if (outUID != null) resp.attach("User-ID", outUID)
    resp.attach("Workspace-ID", outWID)
        .attach("Domain", outDom)
        .attach("Reg-Code", regcode)
        .sendCatching(state.conn, "commandRegCode success message send error")
}

// REGCODE(User-ID, Reg-Code, Password-Hash, Password-Algorithm, Device-ID, Device-Key,
//     Device-Info, Password-Salt="", Password-Parameters="", Domain="")
// REGCODE(Workspace-ID, Reg-Code, Password-Hash, Password-Algorithm, Device-ID, Device-Key,
//     Device-Info, Password-Salt="", Password-Parameters="", Domain="")
fun commandRegCode(state: ClientSession) {

    val schema = Schemas.regCode
    schema.validate(state.message.data) { name, e ->
        val msg = if (e is MissingFieldException)
            "Missing required field $name"
        else
            "Bad value for field $name"
        state.quickResponse(400, "BAD REQUEST", msg)
    } ?: return

    val uid = schema.getUserID("User-ID", state.message.data) ?: run {
        val wid = schema.getRandomID("Workspace-ID", state.message.data) ?: run {
            state.quickResponse(
                400, "BAD REQUEST",
                "Workspace-ID or User-ID required"
            )
            return
        }
        UserID.fromWID(wid)
    }

    // The password field must pass some basic checks for length, but because we will be hashing
    // the thing with Argon2id, even if the client does a dumb thing and submit a cleartext
    // password, there will be a pretty decent baseline of security in place.
    val passHash = schema.getString("Password-Hash", state.message.data)!!
    if (passHash.codePoints().count() !in 16..128) {
        state.quickResponse(400, "BAD REQUEST", "Invalid password hash")
        return
    }

    val regCode = schema.getString("Reg-Code", state.message.data)!!
    if (regCode.codePoints().count() !in 16..128) {
        state.quickResponse(400, "BAD REQUEST", "Invalid registration code")
        return
    }

    val passAlgo = schema.getString("Password-Algorithm", state.message.data)!!

    val devid = schema.getRandomID("Device-ID", state.message.data)!!
    val devkey = schema.getCryptoString("Device-Key", state.message.data)!!
    isSupportedAsymmetric(devkey.prefix).onFalse {
        ServerResponse(
            309, "ENCRYPTION TYPE NOT SUPPORTED",
            "Supported: " + getSupportedAsymmetricAlgorithms().joinToString(",")
        ).sendCatching(
            state.conn,
            "commandRegCode: failed to send bad encryption message"
        )
        return
    }

    val devinfo = schema.getCryptoString("Device-Info", state.message.data)!!
    val domain = schema.getDomain("Domain", state.message.data) ?: gServerDomain
    val passSalt = schema.getString("Password-Salt", state.message.data)
    val passParams = schema.getString("Password-Parameters", state.message.data)

    val db = DBConn()
    val regInfo = checkRegCode(db, MAddress.fromParts(uid, domain), regCode).getOrElse {
        state.internalError(
            "Internal error commandRegCode.checkRegCode: $it",
            "commandRegCode.1"
        )
        return
    } ?: run {
        ServerResponse(401, "UNAUTHORIZED").sendCatching(
            state.conn,
            "commandRegCode: Failed to send unauthorized message"
        )
        return
    }

    // Although we have been given a password hash, we still need to hash it on this side, as well,
    // so that if the client foolishly presented us with a cleartext password, the client's
    // password isn't stored in cleartext in the database.
    val serverHash = Argon2idPassword().updateHash(passHash).getOrElse {
        state.internalError(
            "Internal error commandRegCode.hashPassword: $it",
            "Server error hashing password"
        )
        return
    }
    addWorkspace(
        db, regInfo.first, regInfo.second, domain, serverHash, passAlgo, passSalt ?: "",
        passParams ?: "", WorkspaceStatus.Active, WorkspaceType.Individual
    )?.let {
        if (it is ResourceExistsException) {
            ServerResponse(
                408, "RESOURCE EXISTS",
                "workspace is already registered"
            ).sendCatching(
                state.conn,
                "Failed to send workspace-exists message"
            )
            return
        }
        state.internalError(
            "Internal error commandRegCode.addWorkspace: $it",
            "commandRegCode.2"
        )
        return
    }

    addDevice(db, regInfo.first, devid, devkey, devinfo, DeviceStatus.Registered)?.let {
        state.internalError(
            "commandRegCode.addDevice: $it",
            "commandRegCode.3"
        )
        return
    }

    deletePrereg(db, WAddress.fromParts(regInfo.first, domain))?.let {
        state.internalError(
            "commandRegCode.deletePrereg: $it",
            "commandRegCode.4"
        )
        return
    }

    ServerResponse(201, "REGISTERED")
        .attach("Workspace-ID", regInfo.first)
        .attach("User-ID", uid)
        .attach("Domain", domain)
        .sendCatching(state.conn, "commandRegCode success message send error")
}

// REGISTER(User-ID, Password-Hash, Password-Algorithm, Device-ID, Device-Key,
//     Device-Info, Password-Salt="", Password-Parameters="")
// REGISTER(Workspace-ID, Password-Hash, Password-Algorithm, Device-ID, Device-Key,
//     Device-Info, Password-Salt="", Password-Parameters="")
fun commandRegister(state: ClientSession) {
    val regType = ServerConfig.get().getString("global.registration")!!.lowercase()
    if (regType == "private") {
        state.quickResponse(304, "REGISTRATION CLOSED")
        return
    }

    val schema = Schemas.register
    schema.validate(state.message.data) { name, e ->
        val msg = if (e is MissingFieldException)
            "Missing required field $name"
        else
            "Bad value for field $name"
        state.quickResponse(400, "BAD REQUEST", msg)
    } ?: return

    val db = DBConn()
    val wid = schema.getRandomID("Workspace-ID", state.message.data)
        ?: getFreeWID(db).getOrElse {
            state.internalError(
                "commandRegister.getFreeWID: $it",
                "Error generating workspace ID"
            )
            return
        }
    val uid = schema.getUserID("User-ID", state.message.data)
    val passHash = schema.getString("Password-Hash", state.message.data)!!
    val passAlgo = schema.getString("Password-Algorithm", state.message.data)!!
    val devid = schema.getRandomID("Device-ID", state.message.data)!!
    val devkeyCS = schema.getCryptoString("Device-Key", state.message.data)!!
    val devInfo = schema.getCryptoString("Device-Info", state.message.data)!!
    val passSalt = schema.getString("Password-Salt", state.message.data) ?: ""
    val passParams = schema.getString("Password-Parameters", state.message.data) ?: ""
    val typeStr = schema.getString("Type", state.message.data)

    // The password field must pass some basic checks for length, but because we will be hashing
    // the thing with Argon2id, even if the client does a dumb thing and submit a cleartext
    // password, there will be a pretty decent baseline of security in place.
    if (passHash.length !in 16..128) {
        state.quickResponse(400, "BAD REQUEST", "Invalid password hash")
        return
    }

    val devkey = devkeyCS.toEncryptionKey().getOrElse {
        if (it is UnsupportedAlgorithmException) {
            state.quickResponse(309, "ALGORITHM NOT SUPPORTED")
            return
        }
        state.internalError(
            "Error creating device encryption key for registration: $it",
            "Error creating device encryption key"
        )
        return
    }

    if (typeStr != null) {
        val wType = WorkspaceType.fromString(typeStr) ?: run {
            state.quickResponse(400, "BAD REQUEST", "Bad workspace type")
            return
        }
        // FEATURE: SharedWorkspaces
        // FEATURETODO: Eliminate this Not Implemented response when shared workspaces are implemented
        if (wType == WorkspaceType.Shared) {
            state.quickResponse(301, "NOT IMPLEMENTED")
            return
        }
    }

    checkWorkspace(db, wid).getOrElse {
        state.internalError(
            "commandRegister.checkWorkspace error: $it",
            "Error checking for workspace ID"
        )
        return
    }?.let {
        state.quickResponse(408, "RESOURCE EXISTS")
        return
    }

    resolveUserID(db, uid).getOrElse {
        state.internalError(
            "commandRegister.resolveUserID error: $it",
            "Error checking for user ID"
        )
        return
    }?.let {
        state.quickResponse(408, "RESOURCE EXISTS")
        return
    }

    val wStatus = when (regType) {
        "network" -> {
            checkInRegNetwork(state.conn.inetAddress).getOrElse {
                state.internalError(
                    "commandRegister.checkInRegNetwork error: $it",
                    "Error validating user remote IP"
                )
                return
            }.onFalse {
                state.quickResponse(304, "REGISTRATION CLOSED")
                return
            }
            WorkspaceStatus.Active
        }

        "moderated" -> WorkspaceStatus.Pending
        else -> WorkspaceStatus.Active
    }

    addWorkspace(
        db, wid, uid, gServerDomain, passHash, passAlgo, passSalt, passParams, wStatus,
        WorkspaceType.Individual
    )?.let {
        state.internalError(
            "commandRegister.addWorkspace error: $it",
            "Error adding workspace"
        )
        return
    }

    addDevice(db, wid, devid, devkey.key, devInfo, DeviceStatus.Registered)?.let {
        state.internalError(
            "commandRegister.addDevice error for $wid.$devid: $it",
            "Error adding device"
        )
        return
    }

    val wDirHandle = LocalFS.get().entry(MServerPath("/ wsp $wid"))
    val wDirExists = wDirHandle.exists().getOrElse {
        state.internalError(
            "commandRegister.exists error for $wid.$devid: $it",
            "Error checking existence of workspace directory",
        )
        return
    }
    if (!wDirExists) {
        wDirHandle.makeDirectory()?.let {
            state.internalError(
                "commandRegister.makeDirectory error for $wid.$devid: $it",
                "Error creating workspace directory"
            )
            return
        }
    }

    val response = if (regType == "moderated")
        ServerResponse(101, "PENDING")
    else
        ServerResponse(201, "REGISTERED")
    response.attach("Domain", gServerDomain)
        .attach("Workspace-ID", wid)
        .sendCatching(state.conn, "Error sending registration confirmation msg")
}

private fun checkInRegNetwork(addr: InetAddress): Result<Boolean> {
    // Loopback is always allowed
    if (addr.isLoopbackAddress) return true.toSuccess()

    val addrStr = addr.toString().split('/')[1]
    val ip4networks = ServerConfig.get()
        .getString("global.registration_subnet")
        ?.split(",")
        ?: return ServerException("Missing registration subnet in server config").toFailure()
    ip4networks.forEach { ipstr ->
        CIDRUtils.fromString(ipstr)?.let {
            if (it.isInRange(addrStr).getOrElse { e -> return e.toFailure() })
                return true.toSuccess()
        }
    }

    val ip6networks = ServerConfig.get()
        .getString("global.registration_subnet6")
        ?.split(",")
        ?: return ServerException("Missing registration subnet in server config").toFailure()
    ip6networks.forEach { ipstr ->
        CIDRUtils.fromString(ipstr)?.let {
            if (it.isInRange(addrStr).getOrElse { e -> return e.toFailure() })
                return true.toSuccess()
        }
    }
    return false.toSuccess()
}
