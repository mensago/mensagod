package mensagod

import keznacl.EmptyDataException
import libkeycard.Domain
import java.net.Inet6Address
import java.net.InetAddress

/**
 * The FakeDNSHandler class provides mock DNS information for unit testing purposes
 */
class FakeDNSHandler : DNSHandler() {
    val errors = mutableListOf<FakeDNSError>()
    private val dbConfig = ServerConfig.load()

    /**
     * Normally turns a DNS domain into an IPv4 address. This implementation always returns
     * localhost.
     */
    override fun lookupA(d: String): List<InetAddress> {
        if (errors.isNotEmpty()) {
            when (errors.removeAt(0)) {
                FakeDNSError.Empty -> throw EmptyDataException()
                FakeDNSError.Misconfig -> {
                    return listOf(InetAddress.getByAddress(byteArrayOf(0,0,0,0)))
                }
                FakeDNSError.NoResponse -> throw NetworkErrorException("No response")
                FakeDNSError.NotFound -> throw ResourceNotFoundException()
            }
        }
        return listOf(InetAddress.getByName("127.0.0.1"))
    }

    /**
     * Normally turns a DNS domain into an IPv4 address. This implementation always returns
     * localhost.
     */
    override fun lookupAAAA(d: String): List<InetAddress> {
        if (errors.isNotEmpty()) {
            when (errors.removeAt(0)) {
                FakeDNSError.Empty -> throw EmptyDataException()
                FakeDNSError.Misconfig -> {
                    return listOf(
                        InetAddress.getByAddress(byteArrayOf(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)))
                }
                FakeDNSError.NoResponse -> throw NetworkErrorException("No response")
                FakeDNSError.NotFound -> throw ResourceNotFoundException()
            }
        }
        return listOf(Inet6Address.getByName("::1"))
    }

    /**
     * Normally returns all service records for a domain. This implementation always returns 2
     * records
     */
    override fun lookupSRV(d: String): List<ServiceConfig> {
        if (errors.isNotEmpty()) {
            when (errors.removeAt(0)) {
                FakeDNSError.Empty -> throw EmptyDataException()
                FakeDNSError.Misconfig -> return listOf(
                    ServiceConfig(
                    Domain.fromString("myhostname")!!, 100, 0)
                )
                FakeDNSError.NoResponse -> throw NetworkErrorException("No response")
                FakeDNSError.NotFound -> throw ResourceNotFoundException()
            }
        }
        return listOf(
            ServiceConfig(Domain.fromString("mensago1.example.com")!!, 2001, 0),
            ServiceConfig(Domain.fromString("mensago2.example.com")!!, 2001, 1),
        )
    }

    /**
     * Normally returns all text records for a domain. This implementation always returns two
     * records which contain a PVK and an EK Mensago config item, respectively.
     */
    override fun lookupTXT(d: String): List<String> {
        if (errors.isNotEmpty()) {
            when (errors.removeAt(0)) {
                FakeDNSError.Empty -> throw EmptyDataException()
                FakeDNSError.Misconfig ->  {
                    return listOf("pvk=K12:r#r*RiXIN-0n)BzP3bv`LA&t4LFEQNF0Q@\$N~RF*",
                        "svk=CURVE25519:SNhj2K`hgBd8>G>lW\$!pXiM7S-B!Fbd9jT2&{{Az")
                }
                FakeDNSError.NoResponse -> throw NetworkErrorException("No response")
                FakeDNSError.NotFound -> throw ResourceNotFoundException()
            }
        }

        val db = dbConfig.connectToDB()
        var stmt = db.prepareStatement("SELECT pubkey FROM orgkeys WHERE purpose = 'encrypt';")
        var results = stmt.executeQuery()
        results.next()
        val ek = results.getString(1)

        stmt = db.prepareStatement("SELECT pubkey FROM orgkeys WHERE purpose = 'sign';")
        results = stmt.executeQuery()
        results.next()
        val pvk = results.getString(1)

        stmt = db.prepareStatement("SELECT pubkey FROM orgkeys WHERE purpose = 'altsign';")
        results = stmt.executeQuery()
        return if (results.next())
            listOf("ek=$ek", "pvk=$pvk", "avk=${results.getString(1)}")
        else
            listOf("ek=$ek", "pvk=$pvk")
    }
}

/** FakeDNSError is for simulating different DNS error conditions */
enum class FakeDNSError {
    Empty,
    NoResponse,
    Misconfig,
    NotFound,
}
