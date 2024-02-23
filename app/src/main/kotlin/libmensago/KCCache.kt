package libmensago

import libkeycard.Domain
import libkeycard.Keycard
import libkeycard.MAddress
import libkeycard.RandomID

/**
 * The KCCache class provides thread-safe in-memory keycard caching with an optional second-level
 * database-backed cache. KCCache provides caching for all more-expensive common lookups, not just
 * keycard lookups.
 */
object KCCache {

    fun getKeycard(owner: String?, dns: DNSHandler): Result<Keycard> {
        // TODO: Implement KCCache::getKeycard
        return libmensago.getKeycard(owner, dns)
    }

    fun resolveMenagoAddress(addr: MAddress, dns: DNSHandler): Result<RandomID> {
        // TODO: Implement KCCache::resolveMensagoAddress
        return libmensago.resolveMenagoAddress(addr, dns)
    }

    fun getMgmtRecord(d: Domain, dns: DNSHandler): Result<DNSMgmtRecord> {
        // TODO: implement KCCache::getMgmtRecord
        return libmensago.getMgmtRecord(d, dns)
    }

    fun getRemoteServerConfig(domain: Domain, dns: DNSHandler): Result<List<ServiceConfig>> {
        // TODO: implement KCCache::getRemoteServerConfig
        return libmensago.getRemoteServerConfig(domain, dns)
    }
}
