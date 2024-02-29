package libmensago.resolver

import keznacl.BadValueException
import keznacl.EmptyDataException
import keznacl.toFailure
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
    var keycardCacheCapacity = 100

    private var entries: EntryCache? = null
    private var keycards: KeycardCache? = null

    fun getCurrentEntry(subject: EntrySubject): Result<Entry> {
        val cached = entryCache().get(subject)
        if (cached != null) return cached.toSuccess()
        val entry = getCurrentEntry(subject, dns).getOrElse { return it.toFailure() }
        entryCache().put(entry)
        return entry.toSuccess()
    }

    fun getKeycard(owner: String?): Result<Keycard> {
        // TODO: Migrated KCCache calls to use EntrySubject
        if (owner == null) return EmptyDataException().toFailure()
        val subject = EntrySubject.fromString(owner) ?: return BadValueException().toFailure()

        val cached = keycardCache().get(subject)
        if (cached != null) return cached.toSuccess()
        val keycard = getKeycard(owner, dns).getOrElse { return it.toFailure() }
        keycardCache().put(keycard)
        return keycard.toSuccess()
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

    private fun keycardCache(): KeycardCache {
        if (keycards == null) keycards = KeycardCache(keycardCacheCapacity)
        return keycards!!
    }
}
