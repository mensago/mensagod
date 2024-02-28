package libmensago.resolver

import libkeycard.*
import libmensago.DNSHandler
import libmensago.EntrySubject
import libmensago.ServiceConfig

/**
 * The KCResolver class provides thread-safe in-memory keycard caching with an optional second-level
 * database-backed resolver. KCResolver provides caching for all more-expensive common lookups, not just
 * keycard lookups.
 */
object KCResolver {
    var dns: DNSHandler = DNSHandler()

    fun getCurrentEntry(subject: EntrySubject): Result<Entry> {
        TODO("Implement KCResolver::getCurrentEntry")
    }

    fun getKeycard(owner: String?): Result<Keycard> {
        // TODO: Implement KCResolver::getKeycard
        return getKeycard(owner, dns)
    }

    fun resolveMenagoAddress(addr: MAddress): Result<RandomID> {
        // TODO: Implement KCResolver::resolveMensagoAddress
        return resolveMenagoAddress(addr, dns)
    }

    fun getMgmtRecord(d: Domain): Result<DNSMgmtRecord> {
        // TODO: implement KCResolver::getMgmtRecord
        return getMgmtRecord(d, dns)
    }

    fun getRemoteServerConfig(domain: Domain): Result<List<ServiceConfig>> {
        // TODO: implement KCResolver::getRemoteServerConfig
        return getRemoteServerConfig(domain, dns)
    }
}
