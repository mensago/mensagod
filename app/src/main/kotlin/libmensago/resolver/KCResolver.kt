package libmensago.resolver

import keznacl.toSuccess
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
    var entryCacheCapacity = 100

    private var entries: EntryCache? = null

    fun getCurrentEntry(subject: EntrySubject): Result<Entry> {
        val cached = entryCache().get(subject)
        if (cached != null) return cached.toSuccess()
        return libmensago.resolver.getCurrentEntry(subject, dns)
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

    private fun entryCache(): EntryCache {
        if (entries == null) entries = EntryCache(entryCacheCapacity)
        return entries!!
    }
}
