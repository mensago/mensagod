package libmensago

import keznacl.BadValueException
import keznacl.CryptoString
import keznacl.toFailure
import keznacl.toSuccess
import libkeycard.*
import libmensago.commands.getCard
import libmensago.commands.getWID
import java.io.IOException
import java.net.InetAddress

/**
 * Returns a keycard belonging to the specified owner. To obtain an organization's keycard,
 * pass a domain, e.g. `example.com`. Otherwise obtain a user's keycard by passing either the
 * user's Mensago address or its workspace address. When `force_update` is true, a lookup is
 * forced and the cache is updated regardless of the keycard's TTL expiration status.
 */
fun getKeycard(owner: String?, dns: DNSHandler): Result<Keycard> {

    // First, determine the type of owner. A domain will be passed for an organization, and for
    // a user card a Mensago address or a workspace address will be given.
    val domainTest = Domain.fromString(owner)
    val userTest = MAddress.fromString(owner)
    val isOrg = if (domainTest != null) true else {
        if (userTest == null)
            return Result.failure(BadValueException())
        false
    }
    val domain = if (isOrg) domainTest!! else userTest!!.domain
    val config = getRemoteServerConfig(domain, dns).getOrElse { return it.toFailure() }

    val ip = dns.lookupA(config[0].server.toString()).getOrElse { return it.toFailure() }
    val conn = ServerConnection()
    conn.connect(ip[0], config[0].port).let { if (it != null) return it.toFailure() }


    val card = getCard(conn, owner, 1).getOrElse { return it.toFailure() }
    conn.disconnect()

    return Result.success(card)
}

/** Obtains the workspace ID for a Mensago address */
fun resolveMenagoAddress(addr: MAddress, dns: DNSHandler): Result<RandomID> {

    if (addr.userid.type == IDType.WorkspaceID)
        return Result.success(RandomID.fromString(addr.userid.toString())!!)

    val config = getRemoteServerConfig(addr.domain, dns).getOrElse { return it.toFailure() }
    val ip = dns.lookupA(config[0].server.toString()).getOrElse { return it.toFailure() }
    val conn = ServerConnection()
    conn.connect(ip[0], config[0].port)?.let { return it.toFailure() }

    return getWID(conn, addr.userid, addr.domain)
}

/**
 * Data class to store information contained in a Mensago server's DNS management record.
 */
data class DNSMgmtRecord(
    val pvk: CryptoString, val svk: CryptoString?, val ek: CryptoString,
    val tls: CryptoString?
)

/**
 * This function obtains and returns the information stored in a Mensago server's DNS management
 * record.
 *
 * @exception ResourceNotFoundException Returned if the management record doesn't exist
 * @exception BadValueException Returned for bad data in the management record
 * @exception MissingDataException Returned if a required key is missing from the management record
 * @exception IOException Returned if there was a DNS lookup error
 */
fun getMgmtRecord(d: Domain, dns: DNSHandler): Result<DNSMgmtRecord> {

    val parts = d.toString().split(".")

    if (parts.size == 1) {
        val results = dns.lookupTXT(d.toString()).getOrElse { return it.toFailure() }
        return parseTXTRecords(results)
    }

    var out: DNSMgmtRecord? = null
    for (i in 0 until parts.size - 1) {
        val testParts = mutableListOf("mensago")
        for (j in i until parts.size)
            testParts.add(parts[j])

        val records = dns.lookupTXT(testParts.joinToString("."))
        if (records.isFailure) continue

        out = parseTXTRecords(records.getOrThrow()).getOrElse { return it.toFailure() }
    }

    return out?.toSuccess() ?: ResourceNotFoundException().toFailure()
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
fun getRemoteServerConfig(domain: Domain, dns: DNSHandler): Result<List<ServiceConfig>> {

    val srvRecords = dns.lookupSRV("_mensago._tcp.$domain")
    if (srvRecords.isSuccess) return srvRecords

    val itDomain = Domain.fromString(domain.toString())!!
    while (true) {
        itDomain.push("mensago")

        val ip4 = dns.lookupA(itDomain.toString())
        if (ip4.isSuccess) {
            return Result.success(listOf(ServiceConfig(itDomain, 2001, 0)))
        }

        val ip6 = dns.lookupAAAA(itDomain.toString())
        if (ip6.isSuccess) {
            return Result.success(listOf(ServiceConfig(itDomain, 2001, 0)))
        }
        itDomain.pop()
        if (itDomain.parent() == null) break

        itDomain.pop()
    }

    // Having gotten this far, we have only one other option: attempt to connect to the domain on
    // port 2001.
    val addr = try {
        InetAddress.getByName(itDomain.toString())
    } catch (e: Exception) {
        return Result.failure(e)
    }

    val conn = ServerConnection()
    if (conn.connect(addr, 2001) == null)
        return Result.success(listOf(ServiceConfig(itDomain, 2001, 0)))

    return Result.failure(ResourceNotFoundException())
}

//
/**
 * This private function just finds the management record items in a list of TXT records
 *
 * @exception BadValueException Returned for invalid data in a TXT record
 * @exception MissingDataException Returned if a required key is missing from a Mensago TXT record
 */
private fun parseTXTRecords(records: List<String>): Result<DNSMgmtRecord> {
    // This seemingly pointless construct ensures that we have all the necessary information if,
    // say, the admin put 2 management record items in a TXT record and put another in a second
    // record because they ran out of space in the first one.
    val parts = records.joinToString(" ").split(' ')

    var pvk: CryptoString? = null
    var svk: CryptoString? = null
    var ek: CryptoString? = null
    var tls: CryptoString? = null
    for (part in parts) {
        if (part.length < 5) return Result.failure(BadValueException("Bad TXT record value $part"))

        val lower = part.lowercase()
        when {
            lower.startsWith("pvk=") -> pvk = CryptoString.fromString(part.substring(4))
            lower.startsWith("svk=") -> svk = CryptoString.fromString(part.substring(4))
            lower.startsWith("ek=") -> ek = CryptoString.fromString(part.substring(3))
            lower.startsWith("tls=") -> tls = CryptoString.fromString(part.substring(4))
        }
    }

    if (pvk == null || ek == null)
        return Result.failure(MissingDataException("Required field in management record missing"))

    return Result.success(DNSMgmtRecord(pvk, svk, ek, tls))
}
