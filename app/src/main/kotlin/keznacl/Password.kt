package keznacl

/**
 * An enum class to quickly figure out parameters for a hash function. Basic, despite the usage by
 * GenZ, is good, basic protection, and the other levels are for situations which require more.
 */
enum class HashStrength {
    Basic,
    Extra,
    Secret,
    Extreme,
}

/**
 * Data class used for passing around information about a password without including the hashed
 * password itself.
 */
open class PasswordInfo(
    open var algorithm: String = "",
    open var salt: String = "",
    open var parameters: String = ""
)

/** Parent class for all password hashing algorithms. */
abstract class Password : PasswordInfo() {

    open var hash = ""
    override fun toString(): String {
        return hash
    }

    /**
     * Sets the Password value from an existing password hash.
     *
     * @exception BadValueException Returned if invalid data is passed
     */
    abstract fun setFromHash(hashStr: String): Throwable?

    /**
     * Sets parameters for the algorithm based on the strength requested. The specific parameter
     * values assigned to a strength level is specific to the algorithm.
     */
    abstract fun setStrength(strength: HashStrength): Password

    /** Creates a new hash given a cleartext password. */
    abstract fun updateHash(pw: String): Result<String>

    /** Checks the cleartext password against the object's hash and returns true if they match */
    abstract fun verify(pw: String): Boolean
}

/**
 * Returns the password hashing algorithms supported by the library. Currently the only
 * supported algorithms are Argon2id, Argon2d, and Argon2i. Other algorithms may be added at a
 * future time.
 */
fun getSupportedPasswordAlgorithms(): List<String> {
    return listOf("ARGON2D", "ARGON2I", "ARGON2ID")
}

/**
 * Returns the recommended password hashing algorithm supported by the library. If you don't
 * know what to choose for your implementation, this will provide a good default which balances
 * speed and security.
 */
fun getPreferredPasswordAlgorithm(): String {
    return "ARGON2ID"
}

/**
 * Validates the data in the PasswordInfo instance passed to it. This call ensures that (a) the
 * algorithm used is supported by the library and (b) all required fields for hashing are present
 * and valid.
 */
fun validatePasswordInfo(pi: PasswordInfo): Throwable? {

    val upperAlgo = pi.algorithm.uppercase()
    if (!getSupportedPasswordAlgorithms().contains(upperAlgo))
        return UnsupportedAlgorithmException()

    return when (upperAlgo) {
        "ARGON2D", "ARGON2I", "ARGON2ID" -> Argon2Password.validateInfo(pi)
        else -> UnsupportedAlgorithmException("${pi.algorithm} not supported")
    }
}

/**
 * Validates the passed password info and returns the Password subclass, enabling the caller to
 * hash a password using the process specified in the PasswordInfo instance.
 */
fun passhasherForInfo(pi: PasswordInfo): Result<Password> {
    validatePasswordInfo(pi)?.let { return Result.failure(it) }

    return when (pi.algorithm.uppercase()) {
        "ARGON2D" -> {
            Argon2dPassword().let {
                it.setFromInfo(pi)?.let { err -> return Result.failure(err) }
                Result.success(it)
            }
        }

        "ARGON2I" -> {
            Argon2iPassword().let {
                it.setFromInfo(pi)?.let { err -> return Result.failure(err) }
                Result.success(it)
            }
        }

        "ARGON2ID" -> {
            Argon2idPassword().let {
                it.setFromInfo(pi)?.let { err -> return Result.failure(err) }
                Result.success(it)
            }
        }

        else -> {
            Result.failure(
                ProgramException(
                    "Unreachable code in passhasherForInfo reached. " +
                            "Algorithm: ${pi.algorithm.uppercase()}"
                )
            )
        }
    }
}
