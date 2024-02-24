package libmensago

import libkeycard.Domain
import org.minidns.hla.ResolverApi
import org.minidns.record.A
import org.minidns.record.AAAA
import org.minidns.record.TXT
import java.io.IOException
import java.net.InetAddress

data class ServiceConfig(val server: Domain, val port: Int, val priority: Int)

/**
 * The DNSHandler class is a simple interaction wrapper around DNS lookups that also makes it easy
 * mock out DNS lookups for testing.
 */
open class DNSHandler {

    /** Turns a domain into an IPv4 address */
    open fun lookupA(d: String): Result<List<InetAddress>> {
        val out = mutableListOf<InetAddress>()
        try {
            val result = ResolverApi.INSTANCE.resolve(d, A::class.java)
            if (result.wasSuccessful()) {
                for (record in result.answers)
                    out.add(record.inetAddress)
            }
        } catch (e: Exception) { return Result.failure(e) }

        return Result.success(out)
    }

    /** Turns a domain into an IPv6 address */
    open fun lookupAAAA(d: String): Result<List<InetAddress>> {
        val out = mutableListOf<InetAddress>()
        try {
            val result = ResolverApi.INSTANCE.resolve(d, AAAA::class.java)
            if (result.wasSuccessful()) {
                for (record in result.answers)
                    out.add(record.inetAddress)
            }
        } catch (e: Exception) { return Result.failure(e) }

        return Result.success(out)
    }

    /**
     * Returns all text records for a specific domain. This call is primarily intended for Mensago
     * management record lookups
     *
     * @exception IOException Returned if there was a DNS lookup error
     */
    open fun lookupTXT(d: String): Result<List<String>> {
        val out = mutableListOf<String>()
        try {
            val result = ResolverApi.INSTANCE.resolve(d, TXT::class.java)
            if (result.wasSuccessful()) {
                for (record in result.answers)
                    out.add(record.text)
            }
        } catch (e: Exception) { return Result.failure(e) }

        return Result.success(out)
    }

    /**
     * Returns service records for a specific domain. The information returned consists of a
     * series of tuples containing the domain, the port, and the Time To Live. This call
     * internally sorts the records by priority and weight in descending order such that the
     * first entry in the returned list has the highest priority.
     */
    open fun lookupSRV(d: String): Result<List<ServiceConfig>> {
        val out = mutableListOf<ServiceConfig>()
        try {
            val result = ResolverApi.INSTANCE.resolveSrv(d)
            if (result.wasSuccessful()) {
                for (record in result.answers) {
                    val dom = Domain.fromString(record.target.toString()) ?: continue
                    out.add(ServiceConfig(dom, record.port, record.priority))
                }
            }
        } catch (e: Exception) { return Result.failure(e) }

        out.sortWith(compareBy({it.priority}, {it.server.toString()}))
        return Result.success(out)
    }

}
