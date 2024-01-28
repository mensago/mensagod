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
class LocalFSHandle(val path: MServerPath, private val file: File) {

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
     * Moves the file to the specified directory. Note that the destination MUST point to
     * a directory. The path must also point to a file; moving directories is not supported.
     */
    fun move(dest: MServerPath) {
        TODO("Implement LocalFS::moveFile($dest)")
    }

    /**
     * ReadFile reads data from a file opened with openFile().
     *
     * @throws SecurityException - if a security manager exists and denies read access to the file
     * @throws IOException If there was a problem reading the file
     */
    fun read(): ByteArray { return FileUtils.readFileToByteArray(file) }

    /**
     * Performs a file pointer seek from the file's beginning or, if the offset is negative, from
     * the end of the file.
     */
    fun seek(offset: Int) {
        TODO("Implement LocalFS::seekFile($offset")
    }

    /**
     * Writes data to the file. If you want to append to a file, call seek(-1) first.
     *
     * @return The number of bytes written
     */
    fun write(data: ByteArray): Int {
        TODO("Implement LocalFSHandle::write($data)")
    }
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
     * CopyFile creates a duplicate of the specified source file in the specified destination
     * folder, returning the name of the new file.
     */
    fun copyFile(source: MServerPath, dest: MServerPath): String {
        TODO("Implement LocalFS::copyFile($source, $dest)")
    }

    /**
     * Deletes the file at the specified path.
     *
     * @throws BadValueException If given a bad path
     * @throws SecurityException If a security manager exists and won't let the directory be deleted.
     * @throws FSFailureException For other reasons the system couldn't delete the file
     */
    fun deleteFile(path: MServerPath) {
        val localpath = convertToLocal(path)
        val file = File(localpath.toString())
        if (!file.exists()) return
        if (!file.delete()) throw FSFailureException()
    }

    /**
     * Checks to see if the specified path exists
     *
     * @throws BadValueException If given a bad path
     * @throws SecurityException If a security manager exists and denies read access to the file or directory
     */
    fun exists(path: MServerPath): Boolean {
        val localpath = convertToLocal(path)
        return File(localpath.toString()).exists()
    }

    /**
     * Calculates the disk space usage of a path. If given a file path, it returns the size of the
     * file, but if given a directory path, it calculates the usage of the folder and all of its
     * subfolders.
     */
    fun getDiskUsage(path: MServerPath): Int {
        TODO("Implement LocalFS::getDiskUsage($path)")
    }

    /**
     * Gets a handle in the local filesystem for the path specified.
     *
     * @throws SecurityException - if a security manager exists and denies read access to the file
     */
    fun getFile(path: MServerPath): LocalFSHandle? {
        val localpath = convertToLocal(path)
        if (!localpath.exists()) return null
        return LocalFSHandle(path, File(localpath.toString()))
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
        TODO("Implementnt LocalFS::listFiles($path, $afterTime)")
    }

    /**
     * Creates a directory in the local filesystem within the top-level Mensago directory.
     *
     * @throws BadValueException If given a bad path
     * @throws SecurityException If a security manager exists and won't let the directory be created.
     * @throws FSFailureException For other reasons the system couldn't create a directory, such as a nonexistent parent directory.
     */
    fun makeDirectory(path: MServerPath) {
        val localpath = convertToLocal(path)
        val file = File(localpath.toString())
        if (file.exists()) return
        if (!file.mkdir()) throw FSFailureException()
    }

    /**
     * Moves the specified file to the specified directory. Note that the destination MUST point to
     * a directory.
     */
    fun moveFile(source: MServerPath, dest: MServerPath) {
        TODO("Implement LocalFS::moveFile($source, $dest)")
    }

    /**
     * Removes a directory in the local filesystem. It operates just like the POSIX rmdir command,
     * and will only remove empty directories.
     */
    fun removeDirectory(path: MServerPath) {
        TODO("Implement LocalFS::removeDirectory($path)")
    }

    /**
     * Confirms that the given path is a valid working directory for the user.
     */
    fun select(path: MServerPath): Boolean {
        TODO("Implement LocalFS:select($path)")
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