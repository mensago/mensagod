package mensagod.commands

import mensagod.ClientSession
import mensagod.fs.LocalFS
import mensagod.logError

// UPLOAD(Size,Hash,Path,Replaces="",Name="",Offset=0)
fun commandUpload(state: ClientSession) {

    if (!state.requireLogin()) return
    state.message.validate(setOf("Size", "Path", "Hash"))?.let{
        ServerResponse.sendBadRequest("Missing required field $it", state.conn)
        return
    }

    val hash = state.getCryptoString("Hash", true)
    if (hash == null) {
        ServerResponse.sendBadRequest("Invalid value for Hash", state.conn)
        return
    }

    // Both TempName and Offset must be present when resuming
    val hasTempName = state.message.hasField("TempName")
    val hasOffset = state.message.hasField("Offset")
    if ( (hasTempName && !hasOffset) || (!hasTempName && hasOffset)) {
        ServerResponse.sendBadRequest("Upload resume requires both TempName and Offset fields",
            state.conn)
        return
    }

    val lfs = LocalFS.get()
    val replacesPath = state.getPath("Replaces", false)
    if (replacesPath != null) {
        val handle = try { lfs.entry(replacesPath) }
        catch (e: SecurityException) {
            logError("Error opening path $replacesPath: $e")
            ServerResponse.sendInternalError("commandUpload.1 error", state.conn)
            return
        }

        if (!handle.exists()) {
            ServerResponse(404, "NOT FOUND", "$replacesPath doesn't exist")
                .sendCatching(state.conn, "Client requested nonexistent path $replacesPath")
            return
        }
    } else if (state.message.hasField("Replaces")) {
        ServerResponse.sendBadRequest("Invalid value for Replaces", state.conn)
        return
    }

    val fileSize = try { state.message.data["Size"]!!.toInt() }
    catch (e: Exception) {
        ServerResponse.sendBadRequest("Invalid value for Size", state.conn)
        return
    }

    val uploadPath = state.getPath("Path", true)
    if (uploadPath == null) {
        ServerResponse.sendBadRequest("Invalid value for field Path", state.conn)
        return
    }
    val uploadPathHandle = try { lfs.entry(uploadPath) }
    catch (e: SecurityException) {
        logError("Error opening path $replacesPath: $e")
        ServerResponse.sendInternalError("commandUpload.2 error", state.conn)
        return
    }
    if (!uploadPathHandle.exists()) {
        ServerResponse(404, "NOT FOUND", "$uploadPathHandle doesn't exist")
            .sendCatching(state.conn, "Client requested nonexistent path $uploadPathHandle")
        return
    }

    // TODO: Finish implementing commandUpload()
}