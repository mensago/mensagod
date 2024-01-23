package mensagod.fs

import mensagod.FSFailureException
import mensagod.MServerPath
import mensagod.makeTestFile
import mensagod.setupTest
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.io.File
import java.nio.file.Paths

class LocalFSTest {

    @Test
    fun existsDeleteFileTest() {
        val testdir = setupTest("fs.deleteFile")
        val lfs = LocalFS.get()

        val topdir = Paths.get(testdir, "topdir").toString()
        val testFileInfo = makeTestFile(topdir)

        val testPath = MServerPath("/ ${testFileInfo.first}")
        assert(lfs.exists(testPath))
        lfs.deleteFile(testPath)
        assertFalse(lfs.exists(testPath))
    }

    @Test
    fun makeDirTest() {
        val testdir = setupTest("fs.makeDirectory")
        val lfs = LocalFS.get()

        assertThrows<FSFailureException> {
            lfs.makeDirectory(MServerPath("/ wsp 6e99f804-7bb6-435a-9dce-53d9c6d33816"))
        }

        val wspdir = File(Paths.get(testdir, "topdir", "wsp").toString())
        assert(!wspdir.exists())
        lfs.makeDirectory(MServerPath("/ wsp"))
        assert(wspdir.exists())
    }
}