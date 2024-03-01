package libmensago.resolver

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
    var widCacheCapacity = 500
    var mgmtCacheCapacity = 100
    var svcCacheCapacity = 100

    private var entries: EntryCache? = null
    private var keycards: KeycardCache? = null
    private var wids: WIDCache? = null
    private var mgmts: MgmtCache? = null
    private var svcs: ServiceCache? = null

    fun getCurrentEntry(subject: EntrySubject): Result<Entry> {
        val cached = entryCache().get(subject)
        if (cached != null) return cached.toSuccess()
        val entry = getCurrentEntry(subject, dns).getOrElse { return it.toFailure() }
        entryCache().put(entry)
        return entry.toSuccess()
    }

    private fun entryCache(): EntryCache {
        if (entries == null) entries = EntryCache(entryCacheCapacity)
        return entries!!
    }

    fun getKeycard(subject: EntrySubject): Result<Keycard> {
        val cached = keycardCache().get(subject)
        if (cached != null) return cached.toSuccess()
        val keycard = getKeycard(subject, dns).getOrElse { return it.toFailure() }
        keycardCache().put(keycard)
        return keycard.toSuccess()
    }

    private fun keycardCache(): KeycardCache {
        if (keycards == null) keycards = KeycardCache(keycardCacheCapacity)
        return keycards!!
    }

    fun resolveMenagoAddress(addr: MAddress): Result<RandomID> {
        if (addr.userid.type == IDType.WorkspaceID)
            return addr.userid.toWID()!!.toSuccess()

        val cached = widCache().get(addr)
        if (cached != null) return cached.toSuccess()
        val wid = resolveMenagoAddress(addr, dns).getOrElse { return it.toFailure() }
        widCache().put(addr, wid)
        return wid.toSuccess()
    }

    private fun widCache(): WIDCache {
        if (wids == null) wids = WIDCache(widCacheCapacity)
        return wids!!
    }

    fun getMgmtRecord(d: Domain): Result<DNSMgmtRecord> {
        val cached = mgmtCache().get(d)
        if (cached != null) return cached.toSuccess()
        val rec = getMgmtRecord(d, dns).getOrElse { return it.toFailure() }
        mgmtCache().put(d, rec)
        return rec.toSuccess()
    }

    private fun mgmtCache(): MgmtCache {
        if (mgmts == null) mgmts = MgmtCache(mgmtCacheCapacity)
        return mgmts!!
    }

    fun getRemoteServerConfig(domain: Domain): Result<List<ServiceConfig>> {
        val cached = serviceCache().get(domain)
        if (cached != null) return cached.toSuccess()
        val rec = getRemoteServerConfig(domain, dns).getOrElse { return it.toFailure() }
        serviceCache().put(domain, rec)
        return rec.toSuccess()
    }

    private fun serviceCache(): ServiceCache {
        if (svcs == null) svcs = ServiceCache(svcCacheCapacity)
        return svcs!!
    }
}
