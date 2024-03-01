package libmensago.resolver

import keznacl.BadValueException
import keznacl.toFailure
import keznacl.toSuccess
import libkeycard.*
import libmensago.DNSHandler
import libmensago.EntrySubject
import libmensago.ResourceNotFoundException
import libmensago.ServiceConfig
import java.io.IOException

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

    /**
     * Returns only the current entry for a user or an organization. This call is usually used when
     * the caller is only concerned with the keys published in the entry.
     *
     * @see EntrySubject
     */
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

    /**
     * Returns a keycard belonging to the specified owner. Passing a subject which contains only
     * the domain will result in receiving the organization's keycard. Passing the domain and a
     * UserID will result in receiving a user keycard.
     *
     * @see EntrySubject
     */
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

    /** Obtains the workspace ID for a Mensago address */
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

    /**
     * This function obtains and returns the information stored in a Mensago server's DNS management
     * record.
     *
     * @exception ResourceNotFoundException Returned if the management record doesn't exist
     * @exception BadValueException Returned for bad data in the management record
     * @exception MissingDataException Returned if a required key is missing from the management record
     * @exception IOException Returned if there was a DNS lookup error
     */
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

    /**
     * This function attempts to obtain Mensago server configuration information for the specified
     * domain using the process documented in the spec:
     *
     * 1. Check for an SRV record with the service type `_mensago._tcp`, and use the supplied FQDN
     * and port if it exists
     * 2. Perform an A or AAAA lookup for `mensago.subdomain.example.com`
     * 3. Perform an A or AAAA lookup for `mensago.example.com`
     * 4. Attempt to connect to `example.com`
     *
     * If all of these checks fail, then the domain is assumed to not offer Mensago services and
     * a ResourceNotFoundException will be returned.
     */
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
