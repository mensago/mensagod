package keznacl

import de.mkammerer.argon2.Argon2Advanced
import de.mkammerer.argon2.Argon2Factory
import libkeycard.MissingDataException
import java.nio.charset.Charset
import java.util.*

/** Instantiates an Argon2-family class instance from the supplied hash. */
fun argonPassFromHash(hashStr: String): Result<Argon2Password> {
    hashStr.ifEmpty { return Result.failure(EmptyDataException()) }

    val parts = hashStr.trim().split('$', limit = 3).filter { it.isNotEmpty() }
    if (parts.isEmpty()) return Result.failure(BadValueException())
    val out = when (parts[0]) {
        "argon2d" -> Argon2dPassword()
        "argon2i" -> Argon2idPassword()
        "argon2id" -> Argon2idPassword()
        else -> return Result.failure(BadValueException())
    }
    out.setFromHash(hashStr)?.let { return Result.failure(BadValueException()) }

    return Result.success(out)
}


/**
 * Represents a password and its hash from the Argon2-family. It can also create a hash from a
 * cleartext password. In most situations, you merely need to instantiate an instance of
 * Argon2idPassword and call updateHash(). If you need extra security,
 */
sealed class Argon2Password: Password() {
    protected abstract val hasher: Argon2Advanced
    protected var rawSalt = byteArrayOf()
    var iterations = 10
    var memory = 0x100_000
    var threads = 4
    var version = 19
    override var salt: String
        get() = super.salt
        set(value) {
            rawSalt = Base64.getDecoder().decode(value)
            super.salt = value
        }

    /** Sets the instance's properties from an existing Argon2 hash */
    override fun setFromHash(hashStr: String): Throwable? {
        parseHash(hashStr)?.let { return it }
        hash = hashStr

        return null
    }

    /**
     * Updates the object from a PasswordInfo structure. NOTE: this call only performs basic
     * validation. If you are concerned about the validity of the data in pwInfo, pass it through
     * Argon2Password::validateInfo() first.
     */
    fun setFromInfo(pwInfo: PasswordInfo): Throwable? {
        try {
            salt = pwInfo.salt
        } catch (e: Exception) { return e }

        val paramData = parseParameters(pwInfo.parameters).getOrElse { return it }
        memory = paramData.first
        iterations = paramData.second
        threads = paramData.third

        return null
    }

    /**
     * Sets the general strength of the instance's properties. This affects memory cost,
     * parallelism, and iterations.
     */
    override fun setStrength(strength: HashStrength): Argon2Password {

        memory = when(strength) {
            HashStrength.Basic -> 0x100_000
            HashStrength.Extra -> 0x200_000
            HashStrength.Secret -> 0x400_000
            HashStrength.Extreme -> 0x800_000
        }
        iterations = 10
        threads = 4

        return this
    }

    /**
     * Updates the instance's hash to represent the provided password using the current hash
     * properties and returns the updated value.
     */
    override fun updateHash(pw: String): Result<String> {

        try {
            hash = hasher.hash(iterations, memory, threads, pw.toCharArray(),
                Charset.defaultCharset(), rawSalt)
        }
        catch (e: Exception) { return Result.failure(e) }

        return Result.success(hash)
    }

    /**
     * Returns true if the supplied password matches against the hash stored in the instance.
     * Because there are no guarantees if the instance's cleartext password property is in sync with
     * the hash, this call only compares the supplied password against the hash itself.
     */
    override fun verify(pw: String): Boolean { return hasher.verify(hash, pw.toCharArray()) }

    /**
     * Updates internal properties from the passed hash. It does *not* change the internal hash
     * property itself.
     */
    private fun parseHash(hashStr: String): Throwable? {
        // Sample of the hash format
//      $argon2id$v=19$m=65536,t=2,p=1$azRGvkBtov+ML8kPEaBcIA$tW+o1B8XeLmbKzzN9EQHu9dNLW4T6ia4ha0Z5ZDh7f4

        val parts = hashStr.trim().split('$').filter { it.isNotEmpty() }

        if (parts[0].uppercase() != algorithm) return BadValueException("not an $algorithm hash")

        val versionParts = parts[1].split('=')
        if (versionParts[0] != "v") return BadValueException("second hash field not the version")

        val paramParts = parseParameters(parts[2]).getOrElse { return it }

        try {
            version = versionParts[1].toInt()
            memory = paramParts.first
            iterations = paramParts.second
            threads = paramParts.third
        } catch (e : Exception) { return e }

        parameters = parts[2]
        salt = parts[3]
        rawSalt = try { Base64.getDecoder().decode(salt) }
            catch (e : Exception) { return e }

        return null
    }

    /**
     * Parses out an Argon2 parameter token and returns a triple containing memory, iterations (time
     * cost), and parallelism (threads).
     */
    private fun parseParameters(paramStr: String): Result<Triple<Int,Int,Int>> {
        val paramParts = paramStr
            .split(',')
            .associateBy({it.split('=')[0]},{it.split('=')[1]})
        return try {
            Result.success(Triple(paramParts["m"]!!.toInt(),
                paramParts["t"]!!.toInt(),
                paramParts["p"]!!.toInt()))
        } catch (e : Exception) { return Result.failure(e) }
    }

    companion object {

        /** Ensures that all the hash-related information in the instance is present and valid */
        fun validateInfo(info: PasswordInfo): Throwable? {

            if (info.salt.isEmpty()) return EmptyDataException("Salt missing")
            if (info.parameters.isEmpty()) return EmptyDataException("Hash parameters missing")

            if (!listOf("ARGON2D", "ARGON2I", "ARGON2ID").contains(info.algorithm))
                return BadValueException("${info.algorithm} not supported by Argon2Password class")

            try { Base64.getDecoder().decode(info.salt) }
            catch (e : Exception) { return BadValueException("Undecodable salt") }

            val paramParts = info.parameters
                .split(',')
                .associateBy({it.split('=')[0]},{it.split('=')[1]})

            if (paramParts["m"] != null) {
                try { paramParts["m"]!!.toInt() }
                catch (e: Exception) {
                    return BadValueException("bad memory value in parameters")
                }
            } else return MissingDataException("memory value missing from parameters")

            if (paramParts["t"] != null) {
                try { paramParts["t"]!!.toInt() }
                catch (e: Exception) {
                    return BadValueException("bad time cost value in parameters")
                }
            } else return MissingDataException("time cost value missing from parameters")

            if (paramParts["p"] != null) {
                try { paramParts["p"]!!.toInt() }
                catch (e: Exception) {
                    return BadValueException("bad thread value in parameters")
                }
            } else return MissingDataException("thread value missing from parameters")

            return null
        }
    }
}

/**
 * An Argon2 algorithm which balances protection against brute force attacks and side-channel
 * attacks.
 */
class Argon2idPassword: Argon2Password() {
    override var algorithm = "ARGON2ID"
    override val hasher: Argon2Advanced = Argon2Factory
        .createAdvanced(Argon2Factory.Argon2Types.ARGON2id)

    init {
        rawSalt = hasher.generateSalt()
        salt = Base64.getEncoder().encodeToString(rawSalt)
    }
}

/**
 * An Argon2 algorithm which maximizes protection against GPU-based brute force attacks, but
 * introduces possible side-channel attacks.
 */
class Argon2dPassword: Argon2Password() {
    override var algorithm = "ARGON2D"
    override val hasher: Argon2Advanced = Argon2Factory
        .createAdvanced(Argon2Factory.Argon2Types.ARGON2d)

    init {
        rawSalt = hasher.generateSalt()
        salt = Base64.getEncoder().encodeToString(rawSalt)
    }
}

/** An Argon2 algorithm which is optimized to resist side-channel attacks. */
class Argon2iPassword: Argon2Password() {
    override var algorithm = "ARGON2I"
    override val hasher: Argon2Advanced = Argon2Factory
        .createAdvanced(Argon2Factory.Argon2Types.ARGON2i)

    init {
        rawSalt = hasher.generateSalt()
        salt = Base64.getEncoder().encodeToString(rawSalt)
    }
}

