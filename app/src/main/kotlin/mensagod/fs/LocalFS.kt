package mensagod.fs

import keznacl.BadValueException
import keznacl.CryptoString
import keznacl.getPreferredHashAlgorithm
import libkeycard.RandomID
import mensagod.FSFailureException
import mensagod.MServerPath
import mensagod.ResourceNotFoundException
import mensagod.TypeException
import org.apache.commons.io.FileExistsException
import org.apache.commons.io.FileUtils
import java.io.File
import java.io.IOException
import java.nio.file.DirectoryNotEmptyException
import java.nio.file.Files
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
     * @throws TypeException Returned if given a path which points to a file
     * @throws ResourceNotFoundException Returned if the destination directory doesn't exist
     * @throws IOException Returned if there was a problem copying the file
     * @return The full path of the new file created
     */
    fun copyTo(destPath: MServerPath): Result<MServerPath> {
        val lfs = LocalFS.get()
        val localDest = lfs.convertToLocal(destPath)
        if (!localDest.exists())
            return Result.failure(ResourceNotFoundException("$destPath doesn't exist"))
        if (!localDest.isDirectory())
            return Result.failure(TypeException("$destPath is not a directory"))

        val newID = RandomID.generate().toString()
        val unixTime = System.currentTimeMillis() / 1000L
        val fileSize = FileUtils.sizeOf(file)
        val destName = "$unixTime.$fileSize.$newID"

        val destFile = File(Paths.get(localDest.toString(), destName).toString())
        FileUtils.copyFile(file, destFile)

        return Result.success(destPath.clone().push(destName))
    }

    /**
     * Deletes the file pointed to by the handle. If the handle points to a directory, it will be
     * removed so long as it is empty.
     *
     * @throws DirectoryNotEmptyException Returned if the handle points to a directory and couldn't
     * be deleted because it isn't empty
     * @throws IOException Returned for I/O errors
     * @throws SecurityException Returned if a security manager exists and won't allow the entry
     * to be deleted.
     */
    fun delete(): Throwable? {
        if (file.exists()) {
            try { Files.delete(file.toPath()) }
            catch (e: Exception) { return e }
        }
        return null
    }

    /**
     * Checks to see if the specified path exists
     *
     * @throws BadValueException If given a bad path
     * @throws SecurityException If a security manager exists and denies read access to the file or
     * directory
     */
    fun exists(): Result<Boolean> {
        val out = try { file.exists() }
        catch (e: Exception) { return Result.failure(e) }
        return Result.success(out)
    }

    /** Returns the associated File object for the handle */
    fun getFile(): File { return file }

    /**
     * Creates a hash of the file.
     */
    fun hashFile(algorithm: String = getPreferredHashAlgorithm()): Result<CryptoString> {
        TODO("Implement LocalFSHandle::hashFile($algorithm")
    }

    /**
     * Creates a directory in the local filesystem within the top-level Mensago directory.
     *
     * @throws BadValueException Returned if given a bad path
     * @throws SecurityException Returned if a security manager exists and won't let the directory
     * be created.
     * @throws FSFailureException Returned for other reasons the system couldn't create a directory,
     * such as a nonexistent parent directory.
     */
    fun makeDirectory(): Throwable? {
        if (file.exists()) return null
        return if (file.mkdir()) null else FSFailureException()
    }

    /**
     * Moves the file to the specified directory. Note that the destination MUST point to
     * a directory. The path must also point to a file; moving directories is not supported.
     *
     * @throws ResourceNotFoundException Returned if the destination path doesn't exist
     * @throws TypeException Returned if the destination path points to a file
     * @throws FileExistsException Returned if a file by the same name exists in the destination
     * @throws IOException Returned for I/O errors
     */
    fun moveTo(destPath: MServerPath): Throwable? {
        val lfs = LocalFS.get()
        val localDest = lfs.convertToLocal(destPath)
        if (!localDest.exists()) throw ResourceNotFoundException("$destPath doesn't exist")
        if (!localDest.isDirectory()) throw TypeException("$destPath is not a directory")

        val destFile = File(localDest.toString())
        try { FileUtils.moveFileToDirectory(file, destFile, false) }
        catch (e: Exception) { return e }
        file = File(destFile, file.name)

        return null
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

    /**
     * Modifies the disk usage in the quota information by a relative amount specified in bytes.
     */
    fun modifyQuotaUsage(wid: RandomID, size: Int): Throwable? {
        TODO("Implement modifyQuotaUsage($wid, $size)")
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