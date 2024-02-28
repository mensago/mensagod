package libmensago

import libkeycard.*

/**
 * The KCCache class provides thread-safe in-memory keycard caching with an optional second-level
 * database-backed cache. KCCache provides caching for all more-expensive common lookups, not just
 * keycard lookups.
 */
object KCCache {
    var dns: DNSHandler = DNSHandler()

    fun getCurrentEntry(subject: EntrySubject): Result<Entry> {
        TODO("Implement KCCache::getCurrentEntry")
    }

    fun getKeycard(owner: String?): Result<Keycard> {
        // TODO: Implement KCCache::getKeycard
        return getKeycard(owner, dns)
    }

    fun resolveMenagoAddress(addr: MAddress): Result<RandomID> {
        // TODO: Implement KCCache::resolveMensagoAddress
        return resolveMenagoAddress(addr, dns)
    }

    fun getMgmtRecord(d: Domain): Result<DNSMgmtRecord> {
        // TODO: implement KCCache::getMgmtRecord
        return getMgmtRecord(d, dns)
    }

    fun getRemoteServerConfig(domain: Domain): Result<List<ServiceConfig>> {
        // TODO: implement KCCache::getRemoteServerConfig
        return getRemoteServerConfig(domain, dns)
    }
}
