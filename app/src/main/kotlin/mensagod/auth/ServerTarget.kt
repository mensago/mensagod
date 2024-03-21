package mensagod.auth

import keznacl.toFailure
import keznacl.toSuccess
import libkeycard.MAddress
import libkeycard.UserID
import mensagod.*
import mensagod.dbcmds.resolveAddress
import java.net.Inet4Address

/**
 * The ServerTarget class is used for actions which operate at the server level of scope. This
 * includes workspace registration and preregistration.
 */
class ServerTarget : AuthTarget {

    override fun getActions(actor: AuthActor, action: AuthAction): Result<List<AuthAction>> {
        if (actor.getType() != AuthActorType.WID) return listOf<AuthAction>().toSuccess()
        actor as WIDActor

        if (actor.isAdmin().getOrElse { return it.toFailure() })
            return listOf(AuthAction.Preregister, AuthAction.Archive).toSuccess()

        val out = mutableListOf(AuthAction.Archive)
        val regType = ServerConfig.get().getString("global.registration")!!
        when (regType) {
            "public", "moderated" -> out.add(AuthAction.Register)
            "network" -> {
                actor as SessionActor
                val netListStr = if (actor.ip is Inet4Address)
                    ServerConfig.get().getString("global.registration_subnet")!!
                else
                    ServerConfig.get().getString("global.registration_subnet6")!!

                netListStr.split(",")
                    .map { it.trim() }
                    .filter { it.isNotEmpty() }
                    .mapNotNull { CIDRUtils.fromString(it) }
                    .find { it.isInRange(actor.ip.toString()).getOrDefault(false) }
                    ?.let { out.add(AuthAction.Register) }
            }
        }

        return out.toSuccess()
    }

    override fun isAuthorized(actor: AuthActor, action: AuthAction): Result<Boolean> {
        when (action) {
            AuthAction.Preregister -> {
                // At this point only users may preregister a workspace
                if (actor.getType() != AuthActorType.WID) return false.toSuccess()
                actor as WIDActor

                // For the moment, only the administrator can preregister workspaces
                val addr = MAddress.fromParts(UserID.fromString("admin")!!, gServerDomain)
                val adminWID = withDBResult { db ->
                    resolveAddress(db.connect().getOrThrow(), addr)
                        .getOrElse { db.disconnect(); return it.toFailure() }
                        ?: run {
                            db.disconnect()
                            return DatabaseCorruptionException(
                                "Administrator WID missing from database"
                            ).toFailure()
                        }
                }.getOrElse { return it.toFailure() }

                return Result.success(actor.wid == adminWID)
            }

            else -> return false.toSuccess()
        }
    }
}