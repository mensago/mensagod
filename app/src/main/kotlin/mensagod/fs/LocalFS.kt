package mensagod.fs

import keznacl.BadValueException
import libkeycard.RandomID
import mensagod.FSFailureException
import mensagod.MServerPath
import mensagod.ResourceNotFoundException
import java.io.File
import java.nio.file.Paths
import kotlin.io.path.exists

var localFSSingleton: LocalFS? = null

class LocalFSHandle(val path: String, val file: File)

/**
 * The LocalFS class is an intermediary between the server and the filesystem for workspace access.
 * It provides locking facilities and also provides a measure of insurance that clients cannot
 * access areas of the filesystem outside the specified workspace directory. It also maintains the
 * filesystem permissions subsystem and, thus, maintains a connection to the database for such.
 */
class LocalFS private constructor(private val basePath: String) {
    private val files = mutableSetOf<LocalFSHandle>()
    private val pathSep = System.lineSeparator()

    /**
     * CopyFile creates a duplicate of the specified source file in the specified destination
     * folder, returning the name of the new file.
     */
    fun copyFile(source: MServerPath, dest: MServerPath): String {
        TODO("Implement LocalFS::copyFile($source, $dest)")
    }

    /**
     * Closes the specified file handle. It is not normally needed unless read() returns an error
     * or the caller must abort reading the file.
     */
    fun closeFile(handle: LocalFSHandle): Boolean {
        TODO("Implement LocalFS::closeFile($handle)")
    }

    /**
     * Deletes the file at the specified path.
     *
     * @throws BadValueException If given a bad path
     * @throws SecurityException If a security manager exists and won't let the directory be deleted.
     * @throws FSFailureException For other reasons the system couldn't delete the file
     */
    fun deleteFile(path: MServerPath) {
        val localpath = path.convertToLocal(Paths.get(basePath))
            ?: throw BadValueException("Bad path $path")
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
        val localpath = path.convertToLocal(Paths.get(basePath))
            ?: throw BadValueException("Bad path $path")
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

    /** Moves a file from the temporary file area to a workspace and returns its new name. */
    fun installTempFile(wid: RandomID, name: String, dest: MServerPath): String {
        TODO("Implementnt LocalFS::installTempFile($wid, $name, $dest")
    }

    /** Returns the names of all subdirectories of the specified path */
    fun listDirectories(path: MServerPath): List<MServerPath> {
        TODO("Implementnt LocalFS::listDirectories($path)")
    }

    /**
     * Returns the names of all files in the specified path after the time specified, which is in
     * seconds since the epoch. To return all files, use a 0 for the time.
     */
    fun listFiles(path: MServerPath, afterTime: Int): List<MServerPath> {
        TODO("Implementnt LocalFS::listDirectories($path)")
    }

    /**
     * Creates a directory in the local filesystem within the top-level Mensago directory.
     *
     * @throws BadValueException If given a bad path
     * @throws SecurityException If a security manager exists and won't let the directory be created.
     * @throws FSFailureException For other reasons the system couldn't create a directory, such as a nonexistent parent directory.
     */
    fun makeDirectory(path: MServerPath) {
        val localpath = path.convertToLocal(Paths.get(basePath))
            ?: throw BadValueException("Bad path $path")
        val file = File(localpath.toString())
        if (file.exists()) return
        if (!file.mkdir()) throw FSFailureException()
    }

    /**
     * Creates a file in the temporary file area and returns a handle. The caller is responsible for
     * closing the handle when finished.
     */
    fun makeTempFile(wid: RandomID): LocalFSHandle {
        TODO("Implement LocalFS::makeTempFile($wid)")
    }

    /**
     * Moves the specified file to the specified directory. Note that the destination MUST point to
     * a directory.
     */
    fun moveFile(source: MServerPath, dest: MServerPath) {
        TODO("Implement LocalFS::moveFile($source, $dest)")
    }

    /**
     * Opens the specified file for reading data and returns a file handle.
     */
    fun openFile(path: MServerPath): LocalFSHandle {
        TODO("Implement LocalFS::openFile($path")
    }

    /**
     * Opens the specified temp file for reading or writing. If the offset is >= 0, the read/write
     * pointer is moved to the specified offset. A negative offset moves the read/write pointer from
     * the end of the file. Attempting to open a nonexistent temp file will cause an exception to be
     * thrown.
     */
    fun openTempFile(wid: RandomID, name: String, offset: Int): File {
        TODO("Implement LocalFS::openTempFile($wid, $name, $offset)")
    }

    /**
     * Removes a directory in the local filesystem. It operates just like the POSIX rmdir command,
     * and will only remove empty directories. This command can remove hierarchies of empty
     * directories, but if any non-empty directories are found, an exception is immediately thrown.
     */
    fun removeDirectory(path: MServerPath, recursive: Boolean) {
        TODO("Implement LocalFS::removeDirectory($path, $recursive")
    }


    /**
     * Performs a file pointer seek from the file's beginning or, if the offset is negative, from
     * the end of the file.
     */
    fun seekFile(handle: LocalFSHandle, offset: Int) {
        TODO("Implement LocalFS::seekFile($handle, $offset")
    }

    /**
     * Confirms that the given path is a valid working directory for the user.
     */
    fun select(path: MServerPath) {
        TODO("Implement LocalFS:select($path)")
    }

    companion object {
        fun initialize(basePath: String) {
            val p = Paths.get(basePath)
            if (!p.exists()) throw ResourceNotFoundException("Directory $basePath does not exist")
            localFSSingleton = LocalFS(basePath)
        }

        fun get(): LocalFS { return localFSSingleton!! }
    }
}