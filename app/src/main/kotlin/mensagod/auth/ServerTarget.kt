package mensagod.auth

import libkeycard.MAddress
import libkeycard.UserID
import mensagod.*
import mensagod.dbcmds.resolveAddress
import java.net.Inet4Address

/**
 * The ServerTarget class is used for actions which operate at the server level of scope. This
 * includes workspace registration and preregistration.
 */
class ServerTarget: AuthTarget {

    override fun getActions(actor: AuthActor, action: AuthAction): List<AuthAction> {
        if (actor.getType() != AuthActorType.WID) return listOf()
        actor as WIDActor

        if (actor.isAdmin())
            return listOf(AuthAction.Preregister, AuthAction.Unregister)

        val out = mutableListOf(AuthAction.Unregister)
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

        return out
    }

    override fun isAuthorized(actor: AuthActor, action: AuthAction): Boolean {
        when (action) {
            AuthAction.Preregister -> {
                // At this point only users may preregister a workspace
                if (actor.getType() != AuthActorType.WID) return false
                actor as WIDActor

                // For the moment, only the administrator can preregister workspaces
                val addr = MAddress.fromParts(UserID.fromString("admin")!!, gServerDomain)
                val adminWID = resolveAddress(DBConn().connect().getOrThrow(), addr)
                    ?: throw DatabaseCorruptionException("Administrator WID missing from database")

                return actor.wid == adminWID
            }
            else -> return false
        }
    }
}