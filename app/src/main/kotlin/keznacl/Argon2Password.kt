package keznacl

import de.mkammerer.argon2.Argon2Advanced
import de.mkammerer.argon2.Argon2Factory
import java.nio.charset.Charset
import java.util.*

/**
 * Instantiates an Argon2-family class instance from the supplied hash.
 *
 * @exception EmptyDataException Returned if given an empty string
 * @exception BadValueException Returned if given a string that isn't an Argon2 hash
 */
fun argonPassFromHash(hashStr: String): Result<Argon2Password> {
    hashStr.ifEmpty { return EmptyDataException().toFailure() }

    val parts = hashStr.trim().split('$', limit = 3).filter { it.isNotEmpty() }
    if (parts.isEmpty()) return BadValueException().toFailure()
    val out = when (parts[0]) {
        "argon2d" -> Argon2dPassword()
        "argon2i" -> Argon2idPassword()
        "argon2id" -> Argon2idPassword()
        else -> return BadValueException().toFailure()
    }
    out.setFromHash(hashStr)?.let { return BadValueException().toFailure() }

    return out.toSuccess()
}


/**
 * Represents a password and its hash from the Argon2 family. It can also create a hash from a
 * cleartext password. In most situations, you merely need to instantiate an instance of
 * [Argon2idPassword] and call [updateHash]. The defaults provide good security in many situations,
 * but if you need extra, you can call [setStrength] or set parameters manually.
 */
sealed class Argon2Password : Password() {
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

    /**
     * Sets the instance's properties from an existing Argon2 hash
     *
     * @exception BadValueException Returned if given a bad hash algorithm name or the hash from
     * a different variant of the same algorithm family.
     * @exception NumberFormatException Returned if a hash parameter value or the version is not a
     * number
     * @exception IllegalArgumentException Returned if there is a Base64 decoding error
     */
    override fun setFromHash(hashStr: String): Throwable? {
        parseHash(hashStr)?.let { return it }
        hash = hashStr

        return null
    }

    /**
     * Updates the object from a [PasswordInfo] structure. NOTE: this call only performs basic
     * validation. If you are concerned about the validity of the data in pwInfo, pass it through
     * [Argon2Password.validateInfo] first.
     *
     * @exception NumberFormatException Returned if given non-integers for parameter values
     * @exception IllegalArgumentException Returned for Base64 decoding errors
     */
    fun setFromInfo(pwInfo: PasswordInfo): Throwable? {
        runCatching {
            salt = pwInfo.salt
        }.getOrElse { return it }

        val paramData = parseParameters(pwInfo.parameters).getOrElse { return it }
        memory = paramData.first
        iterations = paramData.second
        threads = paramData.third

        return null
    }

    /**
     * Sets the general strength of the instance's properties. This affects memory cost,
     * parallelism, and iterations.
     *
     * @return Reference to the current object
     */
    override fun setStrength(strength: HashStrength): Argon2Password {

        memory = when (strength) {
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

        runCatching {
            hash = hasher.hash(
                iterations, memory, threads, pw.toCharArray(),
                Charset.defaultCharset(), rawSalt
            )
        }.getOrElse { return it.toFailure() }

        return hash.toSuccess()
    }

    /**
     * Returns true if the supplied password matches against the hash stored in the instance.
     * Because there are no guarantees if the instance's cleartext password property is in sync with
     * the hash, this call only compares the supplied password against the hash itself.
     */
    override fun verify(pw: String): Boolean {
        return hasher.verify(hash, pw.toCharArray())
    }

    /**
     * Updates internal properties from the passed hash. It does *not* change the internal hash
     * property itself.
     *
     * @exception BadValueException Returned if given a bad hash algorithm name
     * @exception NumberFormatException Returned if a hash parameter value or the version is not a
     * number
     * @exception IllegalArgumentException Returned if there is a Base64 decoding error
     */
    private fun parseHash(hashStr: String): Throwable? {
        // Sample of the hash format
//      $argon2id$v=19$m=65536,t=2,p=1$azRGvkBtov+ML8kPEaBcIA$tW+o1B8XeLmbKzzN9EQHu9dNLW4T6ia4ha0Z5ZDh7f4

        val parts = hashStr.trim().split('$').filter { it.isNotEmpty() }

        if (parts[0].uppercase() != algorithm) return BadValueException("not an $algorithm hash")

        val versionParts = parts[1].split('=')
        if (versionParts[0] != "v") return BadValueException("second hash field not the version")

        val paramParts = parseParameters(parts[2]).getOrElse { return it }

        runCatching {
            version = versionParts[1].toInt()
            memory = paramParts.first
            iterations = paramParts.second
            threads = paramParts.third
        }.getOrElse { return it }

        parameters = parts[2]
        salt = parts[3]
        rawSalt = runCatching { Base64.getDecoder().decode(salt) }.getOrElse { return it }

        return null
    }

    /**
     * Parses out an Argon2 parameter token and returns a triple containing memory, iterations (time
     * cost), and parallelism (threads).
     *
     * @exception NumberFormatException Returned if given non-integers for parameter values
     */
    private fun parseParameters(paramStr: String): Result<Triple<Int, Int, Int>> {
        val paramParts = paramStr
            .split(',')
            .associateBy({ it.split('=')[0] }, { it.split('=')[1] })
        return runCatching {
            Triple(
                paramParts["m"]!!.toInt(),
                paramParts["t"]!!.toInt(),
                paramParts["p"]!!.toInt()
            ).toSuccess()
        }.getOrElse { it.toFailure() }
    }

    companion object {

        /**
         * Ensures that all the hash-related information in the instance is present and valid
         *
         * @exception IllegalArgumentException Returned for Base64 decoding errors
         */
        fun validateInfo(info: PasswordInfo): Throwable? {

            if (info.salt.isEmpty()) return EmptyDataException("Salt missing")
            if (info.parameters.isEmpty()) return EmptyDataException("Hash parameters missing")

            if (!listOf("ARGON2D", "ARGON2I", "ARGON2ID").contains(info.algorithm))
                return BadValueException("${info.algorithm} not supported by Argon2Password class")

            runCatching {
                Base64.getDecoder().decode(info.salt)
            }.getOrElse {
                return IllegalArgumentException()
            }

            val paramParts = info.parameters
                .split(',')
                .associateBy({ it.split('=')[0] }, { it.split('=')[1] })

            if (paramParts["m"] != null) {
                runCatching {
                    paramParts["m"]!!.toInt()
                }.getOrElse {
                    return BadValueException("bad memory value in parameters")
                }
            } else return MissingDataException("memory value missing from parameters")

            if (paramParts["t"] != null) {
                runCatching {
                    paramParts["t"]!!.toInt()
                }.getOrElse {
                    return BadValueException("bad time cost value in parameters")
                }
            } else return MissingDataException("time cost value missing from parameters")

            if (paramParts["p"] != null) {
                runCatching {
                    paramParts["p"]!!.toInt()
                }.getOrElse {
                    return BadValueException("bad thread value in parameters")
                }
            } else return MissingDataException("thread value missing from parameters")

            return null
        }
    }
}

/**
 * An Argon2 algorithm which balances protection against brute force attacks and side-channel
 * attacks. If you're not sure which of the three Argon variants to choose, pick this one.
 */
class Argon2idPassword : Argon2Password() {
    override var algorithm = "ARGON2ID"
    override val hasher: Argon2Advanced = Argon2Factory
        .createAdvanced(Argon2Factory.Argon2Types.ARGON2id)

    init {
        rawSalt = hasher.generateSalt()
        salt = Base64.getEncoder().withoutPadding().encodeToString(rawSalt)
    }
}

/**
 * An Argon2 algorithm which maximizes protection against GPU-based brute force attacks, but
 * introduces possible side-channel attacks.
 */
class Argon2dPassword : Argon2Password() {
    override var algorithm = "ARGON2D"
    override val hasher: Argon2Advanced = Argon2Factory
        .createAdvanced(Argon2Factory.Argon2Types.ARGON2d)

    init {
        rawSalt = hasher.generateSalt()
        salt = Base64.getEncoder().withoutPadding().encodeToString(rawSalt)
    }
}

/** An Argon2 algorithm which is optimized to resist side-channel attacks. */
class Argon2iPassword : Argon2Password() {
    override var algorithm = "ARGON2I"
    override val hasher: Argon2Advanced = Argon2Factory
        .createAdvanced(Argon2Factory.Argon2Types.ARGON2i)

    init {
        rawSalt = hasher.generateSalt()
        salt = Base64.getEncoder().withoutPadding().encodeToString(rawSalt)
    }
}
