package mensagod

import keznacl.BadValueException
import java.util.regex.Pattern

/**
 * The MServerPath class encapsulates the ability work with server-side Mensago paths. These paths
 * have path components separated by a space. The server-side variant always begins with "/", a
 * top-level specifier ('wsp', 'tmp', or 'out') and a series of lowercase UUIDs. This is to ensure
 * maximum privacy for users.
 */
class MServerPath {
    private var value = "/"
    private var parts = value.split(" ").toMutableList()

    /** Returns the name of the item specified, regardless of if it's a folder or file. */
    fun basename(): String {
        return parts.last()
    }

    /** Returns the object's path */
    fun get(): String { return value }

    /** Returns true if the instance's path represents a file */
    fun isFile(): Boolean { return fileRE.matches(parts.last()) }

    /** Returns true if the instance's path represents a directory */
    fun isDir(): Boolean { return !isFile() }

    /** Returns true if the path represents the root directory */
    fun isRoot(): Boolean { return value == "/" }

    /**
     * Returns the path containing the object's parent. If the instance is set to the path root (/),
     * null will be returned.
     */
    fun parent(): MServerPath? {
        return if (value == "/") null else {
            val joined = value.split(" ").dropLast(1).joinToString(" ")
            if (joined.trim().isEmpty()) return null
            fromString(joined)
        }
    }

    /**
     * Appends the supplied path to the object.
     *
     * @throws InvalidPathException If the path currently points to a file
     * @throws BadValueException If given an invalid path argument
     */
    fun push(s: String) {
        if (fileRE.matches(parts.last())) throw InvalidPathException()

        val trimmed = s.trim().trim('/')
        val newPath = "$value $trimmed"
        if (!serverPathRE.matches(newPath)) throw BadValueException()
        value = newPath
        parts = value.split("/").toMutableList()
    }

    /** Sets the value of the object or returns an error if given an invalid path */
    fun set(s: String): Throwable? {
        if (!serverPathRE.matches(s)) return BadValueException()
        value = s
        parts = value.split(" ").toMutableList()
        return null
    }

    override fun toString(): String { return value }

    companion object {
        private val fileRE = Pattern.compile(
            """^[0-9]+.[0-9]+.[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$"""
        ).toRegex()
        private val serverPathRE = Pattern.compile(
                """^/( wsp| out| tmp)?""" +
                """( [0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12})*""" +
                """( new)?( [0-9]+.[0-9]+.""" +
                """[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12})*"""
        ).toRegex()

        fun validateFilePath(s: String): Boolean { return fileRE.matches(s) }
        fun validateDirPath(s: String): Boolean { return serverPathRE.matches(s) }

        fun fromString(path: String): MServerPath? {
            val out = MServerPath()
            return if (out.set(path) == null) out else null
        }
    }
}