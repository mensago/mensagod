package testsupport

import keznacl.EmptyDataException
import keznacl.toFailure
import keznacl.toSuccess
import libkeycard.Domain
import libmensago.DNSHandler
import libmensago.NetworkErrorException
import libmensago.ResourceNotFoundException
import libmensago.ServiceConfig
import mensagod.DBConn
import java.net.Inet6Address
import java.net.InetAddress

/**
 * The FakeDNSHandler class provides mock DNS information for unit testing purposes
 */
class FakeDNSHandler : DNSHandler() {
    private val errors = mutableListOf<FakeDNSError>()

    /**
     * Normally turns a DNS domain into an IPv4 address. This implementation always returns
     * localhost.
     */
    override fun lookupA(d: String): Result<List<InetAddress>> {
        if (errors.isNotEmpty()) {
            return when (errors.removeAt(0)) {
                FakeDNSError.Empty -> EmptyDataException().toFailure()
                FakeDNSError.Misconfig ->
                    listOf(InetAddress.getByAddress(byteArrayOf(0, 0, 0, 0))).toSuccess()

                FakeDNSError.NoResponse -> NetworkErrorException("No response").toFailure()
                FakeDNSError.NotFound -> ResourceNotFoundException().toFailure()
            }
        }
        return listOf(InetAddress.getByName("127.0.0.1")).toSuccess()
    }

    /**
     * Normally turns a DNS domain into an IPv4 address. This implementation always returns
     * localhost.
     */
    override fun lookupAAAA(d: String): Result<List<InetAddress>> {
        if (errors.isNotEmpty()) {
            return when (errors.removeAt(0)) {
                FakeDNSError.Empty -> EmptyDataException().toFailure()
                FakeDNSError.Misconfig -> listOf(
                    InetAddress.getByAddress(
                        byteArrayOf(
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0
                        )
                    )
                ).toSuccess()

                FakeDNSError.NoResponse -> NetworkErrorException("No response").toFailure()
                FakeDNSError.NotFound -> ResourceNotFoundException().toFailure()
            }
        }
        return listOf(Inet6Address.getByName("::1")).toSuccess()
    }

    /**
     * Normally returns all service records for a domain. This implementation always returns 2
     * records
     */
    override fun lookupSRV(d: String): Result<List<ServiceConfig>> {
        if (errors.isNotEmpty()) {
            return when (errors.removeAt(0)) {
                FakeDNSError.Empty -> EmptyDataException().toFailure()
                FakeDNSError.Misconfig -> listOf(
                    ServiceConfig(
                        Domain.fromString("myhostname")!!, 100, 0
                    )
                ).toSuccess()

                FakeDNSError.NoResponse -> NetworkErrorException("No response").toFailure()
                FakeDNSError.NotFound -> ResourceNotFoundException().toFailure()
            }
        }
        return listOf(
            ServiceConfig(Domain.fromString("mensago1.example.com")!!, 2001, 0),
            ServiceConfig(Domain.fromString("mensago2.example.com")!!, 2001, 1),
        ).toSuccess()
    }

    /**
     * Normally returns all text records for a domain. This implementation always returns two
     * records which contain a PVK and an EK Mensago config item, respectively.
     */
    override fun lookupTXT(d: String): Result<List<String>> {
        if (errors.isNotEmpty()) {
            return when (errors.removeAt(0)) {
                FakeDNSError.Empty -> EmptyDataException().toFailure()
                FakeDNSError.Misconfig -> listOf(
                    "pvk=K12:r#r*RiXIN-0n)BzP3bv`LA&t4LFEQNF0Q@\$N~RF*",
                    "svk=CURVE25519:SNhj2K`hgBd8>G>lW\$!pXiM7S-B!Fbd9jT2&{{Az"
                ).toSuccess()

                FakeDNSError.NoResponse -> NetworkErrorException("No response").toFailure()
                FakeDNSError.NotFound -> ResourceNotFoundException().toFailure()
            }
        }

        val db = DBConn()
        var rs = db.query("SELECT pubkey FROM orgkeys WHERE purpose = 'encrypt';").getOrThrow()
        rs.next()
        val ek = rs.getString(1)

        rs = db.query("SELECT pubkey FROM orgkeys WHERE purpose = 'sign';").getOrThrow()
        rs.next()
        val pvk = rs.getString(1)

        rs = db.query("SELECT pubkey FROM orgkeys WHERE purpose = 'altsign';").getOrThrow()
        return if (rs.next())
            listOf("ek=$ek", "pvk=$pvk", "avk=${rs.getString(1)}").toSuccess()
        else
            listOf("ek=$ek", "pvk=$pvk").toSuccess()
    }
}

/** FakeDNSError is for simulating different DNS error conditions */
enum class FakeDNSError {
    Empty,
    NoResponse,
    Misconfig,
    NotFound,
}
