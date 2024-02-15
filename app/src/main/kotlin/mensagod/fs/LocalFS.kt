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
import java.time.Instant
import java.util.*
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

        return destPath.clone().push(destName)
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
        return keznacl.hashFile(file.path.toString(), algorithm)
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
     * readAll reads data from a file into memory.
     *
     * @throws ResourceNotFoundException Returned if the file doesn't exist
     * @throws SecurityException Returned if a security manager exists and denies read access to the
     * file
     * @throws IOException Returned if there was a problem reading the file
     */
    fun readAll(): Result<ByteArray> {
        if (!file.exists()) return Result.failure(ResourceNotFoundException())
        return try { Result.success(FileUtils.readFileToByteArray(file)) }
        catch (e: Exception) { Result.failure(e) }
    }

    /**
     * size returns the size of the file.
     *
     * @throws SecurityException Returned if a security manager exists and denies read access to the
     * file
     */
    fun size(): Result<Long> {
        return try { Result.success(file.length()) }
            catch (e: Exception) { Result.failure(e) }
    }
}

/**
 * The LocalFS class is an intermediary between the server and the filesystem for workspace access.
 * It provides locking facilities and also provides a measure of insurance that clients cannot
 * access areas of the filesystem outside the specified workspace directory. It also maintains the
 * filesystem permissions subsystem and, thus, maintains a connection to the database for such.
 */
class LocalFS private constructor(val basePath: Path) {

    private val locks = mutableSetOf<String>()

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
     * a file or directory doesn't necessarily mean that said entity actually exists.
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
     * @throws ResourceNotFoundException Returned if the destination doesn't exist
     * @throws IOException Returned on I/O errors
     */
    fun getDiskUsage(path: MServerPath): Result<Long> {
        val localPath = convertToLocal(path)
        val pathFile = File(localPath.toString())
        if (!pathFile.exists()) return Result.failure(ResourceNotFoundException())

        return try { Result.success(FileUtils.sizeOf(pathFile)) }
        catch (e: Exception) { Result.failure(e) }
    }

    /** Creates a lock on a filesystem entry. */
    fun lock(path: MServerPath) = synchronized(locks) { locks.add(path.toString()) }

    /**
     * Creates a handle for a temporary file. The file itself doesn't exist, but this gets rid of
     * all the boilerplate code needed to prepare one.
     */
    fun makeTempFile(wid: RandomID, fileSize: Long): Result<LocalFSHandle> {
        val widTempPath = Paths.get(basePath.toString(), "tmp", wid.toString())
        val out = try {
            widTempPath.toFile().mkdirs()
            val tempName =
                "${Instant.now().epochSecond}.fileSize.${UUID.randomUUID().toString().lowercase()}"
            val tempFile = Paths.get(widTempPath.toString(), tempName).toFile()
            val tempMPath = MServerPath("/ tmp $wid $tempName")
            LocalFSHandle(tempMPath, tempFile)
        }
        catch (e: Exception) { return Result.failure(e) }
        return Result.success(out)
    }

    /** Removes the lock on a filesystem entry. */
    fun unlock(path: MServerPath) = synchronized(locks) { locks.remove(path.toString()) }

    /**
     * Runs a block of code while locking a filesystem entity.
     */
    fun withLock(path: MServerPath, lockfun: (p: MServerPath) -> Throwable?): Throwable? {
        lock(path)
        val out = lockfun(path)
        unlock(path)
        return out
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