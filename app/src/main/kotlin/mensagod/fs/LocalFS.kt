package mensagod.fs

import keznacl.BadValueException
import libkeycard.RandomID
import mensagod.FSFailureException
import mensagod.MServerPath
import mensagod.ResourceNotFoundException
import mensagod.TypeException
import org.apache.commons.io.FileUtils
import java.io.File
import java.io.IOException
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.io.path.exists
import kotlin.io.path.isDirectory

var localFSSingleton: LocalFS? = null

/**
 * The LocalFSHandle class provides an API which could be easily abstracted to an interface for
 * interacting with a filesystem in a generic way, enabling potential usage of S3, SANs, or other
 * non-local storage media.
 */
class LocalFSHandle(val path: MServerPath, private var file: File) {

    /**
     * Creates a duplicate of the file in another directory. The destination path MUST point to a
     * directory.
     *
     * @throws TypeException If given a path which points to a file
     * @throws ResourceNotFoundException If the destination directory doesn't exist
     * @throws IOException If there was a problem copying the file
     * @return The full path of the new file created
     */
    fun copyTo(destPath: MServerPath): MServerPath {
        val lfs = LocalFS.get()
        val localDest = lfs.convertToLocal(destPath)
        if (!localDest.exists()) throw ResourceNotFoundException("$destPath doesn't exist")
        if (!localDest.isDirectory()) throw TypeException("$destPath is not a directory")

        val destName = RandomID.generate().toString()
        val destFile = File(Paths.get(localDest.toString(), destName).toString())
        FileUtils.copyFile(file, destFile)

        return MServerPath(destPath.toString()).push(destName)
    }

    /**
     * Deletes the file pointed to by the handle. If the handle points to a directory, it will be
     * removed so long as it is empty.
     */
    fun delete() { if (file.exists()) file.delete() }

    /**
     * Checks to see if the specified path exists
     *
     * @throws BadValueException If given a bad path
     * @throws SecurityException If a security manager exists and denies read access to the file or directory
     */
    fun exists(): Boolean { return file.exists() }

    /**
     * Creates a directory in the local filesystem within the top-level Mensago directory.
     *
     * @throws BadValueException If given a bad path
     * @throws SecurityException If a security manager exists and won't let the directory be created.
     * @throws FSFailureException For other reasons the system couldn't create a directory, such as a nonexistent parent directory.
     */
    fun makeDirectory() {
        if (file.exists()) return
        if (!file.mkdir()) throw FSFailureException()
    }

    /**
     * Moves the file to the specified directory. Note that the destination MUST point to
     * a directory. The path must also point to a file; moving directories is not supported.
     */
    fun move(destPath: MServerPath) {
        val lfs = LocalFS.get()
        val localDest = lfs.convertToLocal(destPath)
        if (!localDest.exists()) throw ResourceNotFoundException("$destPath doesn't exist")
        if (!localDest.isDirectory()) throw TypeException("$destPath is not a directory")

        val destFile = File(localDest.toString())
        FileUtils.moveFileToDirectory(file, destFile, false)
        file = File(destFile, file.name)
    }

    /**
     * ReadFile reads data from a file opened with openFile().
     *
     * @throws SecurityException - if a security manager exists and denies read access to the file
     * @throws IOException If there was a problem reading the file
     */
    fun readAll(): ByteArray { return FileUtils.readFileToByteArray(file) }

    /**
     * Writes data to a file
     *
     * @return The number of bytes written
     */
    fun writeAll(data: ByteArray) { return FileUtils.writeByteArrayToFile(file, data) }
}

/**
 * The LocalFS class is an intermediary between the server and the filesystem for workspace access.
 * It provides locking facilities and also provides a measure of insurance that clients cannot
 * access areas of the filesystem outside the specified workspace directory. It also maintains the
 * filesystem permissions subsystem and, thus, maintains a connection to the database for such.
 */
class LocalFS private constructor(val basePath: Path) {
    private val pathSep = System.lineSeparator()

    /**
     * Converts the server path to a local filesystem path format. The output path is relative to
     * the local path provided, e.g '/ wsp foo' relative to '/var/mensagod' would become
     * '/var/mensago/wsp/foo'.
     */
    fun convertToLocal(path: MServerPath): Path {
        if (path.isRoot())
            return basePath

        val joined = path.parts.subList(1, path.parts.size).joinToString(File.separator)
        return Paths.get(basePath.toString(), joined)
    }

    /**
     * Gets a handle in the local filesystem for the path specified. Note that getting a handle to
     * a file or directory necessarily means that said entity actually exists.
     *
     * @throws SecurityException - if a security manager exists and denies read access to the file
     */
    fun entry(path: MServerPath): LocalFSHandle {
        val localpath = convertToLocal(path)
        return LocalFSHandle(path, File(localpath.toString()))
    }

    /**
     * Calculates the disk space usage of a path. If given a file path, it returns the size of the
     * file, but if given a directory path, it calculates the usage of the folder and all of its
     * subfolders.
     *
     * @throws ResourceNotFoundException If the destination doesn't exist
     */
    fun getDiskUsage(path: MServerPath): Long {
        val localPath = convertToLocal(path)
        val pathFile = File(localPath.toString())
        if (!pathFile.exists()) throw ResourceNotFoundException()
        return FileUtils.sizeOf(pathFile)
    }

    /** Returns the names of all immediate subdirectories of the specified path */
    fun listDirectories(path: MServerPath): List<MServerPath> {
        TODO("Implement LocalFS::listDirectories($path)")
    }

    /**
     * Returns the names of all files in the specified path after the time specified, which is in
     * seconds since the epoch. To return all files, use a 0 for the time.
     */
    fun listFiles(path: MServerPath, afterTime: Int): List<MServerPath> {
        TODO("Implement LocalFS::listFiles($path, $afterTime)")
    }

    companion object {
        fun initialize(basePath: String) {
            val p = Paths.get(basePath)
            if (!p.exists()) throw ResourceNotFoundException("Directory $basePath does not exist")
            localFSSingleton = LocalFS(p)
        }

        fun get(): LocalFS { return localFSSingleton!! }
    }
}