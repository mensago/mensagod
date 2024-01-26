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
        val setupData = setupTest("fs.deleteFile")
        val lfs = LocalFS.get()

        val topdir = Paths.get(setupData.testPath, "topdir").toString()
        val testFileInfo = makeTestFile(topdir)

        val testPath = MServerPath("/ ${testFileInfo.first}")
        assert(lfs.exists(testPath))
        lfs.deleteFile(testPath)
        assertFalse(lfs.exists(testPath))
    }

    @Test
    fun makeDirTest() {
        val setupData = setupTest("fs.makeDirectory")
        val lfs = LocalFS.get()

        assertThrows<FSFailureException> {
            lfs.makeDirectory(MServerPath(
                "/ wsp 6e99f804-7bb6-435a-9dce-53d9c6d33816 5769bf90-aeb2-46b1-9bc5-4809d55991df"))
        }

        val wspdir = File(Paths.get(setupData.testPath, "topdir", "wsp",
            "6e99f804-7bb6-435a-9dce-53d9c6d33816").toString())
        assert(!wspdir.exists())
        lfs.makeDirectory(MServerPath("/ wsp 6e99f804-7bb6-435a-9dce-53d9c6d33816"))
        assert(wspdir.exists())
    }
}