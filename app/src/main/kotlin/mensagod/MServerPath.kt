package mensagod

import keznacl.BadValueException
import java.io.File
import java.nio.file.Path
import java.nio.file.Paths
import java.util.regex.Pattern

/**
 * The MServerPath class encapsulates the ability work with server-side Mensago paths. These paths
 * have path components separated by a space. The server-side variant always begins with "/", a
 * top-level specifier ('wsp', 'tmp', or 'out') and a series of lowercase UUIDs. This is to ensure
 * maximum privacy for users.
 */
class MServerPath(path: String? = null) {
    private var value = "/"
    private var parts = value.split(" ").toMutableList()

    init {
        if (path != null) {
            if (set(path) == null) throw BadValueException()
        }
    }

    /** Returns the name of the item specified, regardless of if it's a folder or file. */
    fun basename(): String {
        return parts.last()
    }

    /**
     * Converts the server path to a local filesystem path format. The output path is relative to
     * the local path provided, e.g '/ wsp foo' relative to '/var/mensagod' would become
     * '/var/mensago/wsp/foo'.
     */
    fun convertToLocal(topdir: Path?): Path? {
        if (isRoot()) {
            return topdir
                ?: if (platformIsWindows) {
                    Paths.get("\\")
                } else {
                    Paths.get("/")
                }
        }
        val joined = parts.subList(1, parts.size).joinToString(File.separator)
        return Paths.get(topdir?.toString() ?: File.separator, joined)
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
    fun push(s: String): MServerPath {
        if (fileRE.matches(parts.last())) throw InvalidPathException()

        val trimmed = s.trim().trim('/')
        val newPath = "$value $trimmed"
        if (!serverPathRE.matches(newPath)) throw BadValueException()
        value = newPath
        parts = value.split("/").toMutableList()

        return this
    }

    /**
     * Sets the value of the object and returns its reference or null if given an invalid path
     */
    fun set(s: String): MServerPath? {
        if (!serverPathRE.matches(s)) return null
        value = s
        parts = value.split(" ").toMutableList()
        return this
    }

    override fun toString(): String { return value }

    companion object {
        private val fileRE = Pattern.compile(
            """^[0-9]+.[0-9]+.[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$"""
        ).toRegex()
        private val serverPathRE = Pattern.compile(
                """^/( wsp| out| tmp| keys)?""" +
                """( [0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12})*""" +
                """( new)?( [0-9]+.[0-9]+.""" +
                """[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12})*"""
        ).toRegex()

        fun validateFilePath(s: String): Boolean { return fileRE.matches(s) }
        fun validateDirPath(s: String): Boolean { return serverPathRE.matches(s) }

        fun fromString(path: String): MServerPath? { return MServerPath().set(path) }
    }
}