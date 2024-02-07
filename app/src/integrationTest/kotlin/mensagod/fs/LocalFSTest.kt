package mensagod.fs

import mensagod.FSFailureException
import mensagod.MServerPath
import mensagod.makeTestFile
import mensagod.setupTest
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.io.File
import java.nio.file.Paths

class LocalFSTest {

    @Test
    fun convertTest() {
        setupTest("fs.convertTest")
        val lfs = LocalFS.get()

        val converted = Paths.get(lfs.basePath.toString(), "wsp",
            "d8b6d06b-7728-4c43-bc08-85a0c645d260").toString()

        Assertions.assertEquals(converted, lfs.convertToLocal(
            MServerPath("/ wsp d8b6d06b-7728-4c43-bc08-85a0c645d260")).toString())
    }

    @Test
    fun existsDeleteFileTest() {
        val setupData = setupTest("fs.deleteFile")
        val lfs = LocalFS.get()

        val topdir = Paths.get(setupData.testPath, "topdir").toString()
        val testFileInfo = makeTestFile(topdir)

        val handle = lfs.entry(MServerPath("/ ${testFileInfo.first}"))
        assert(handle.exists().getOrThrow())
        handle.delete()
        assertFalse(handle.exists().getOrThrow())
    }

    @Test
    fun makeDirTest() {
        val setupData = setupTest("fs.makeDirectory")
        val lfs = LocalFS.get()

        assertThrows<FSFailureException> {
            lfs.entry(MServerPath(
                "/ wsp 6e99f804-7bb6-435a-9dce-53d9c6d33816 5769bf90-aeb2-46b1-9bc5-4809d55991df"))
                .makeDirectory()
                ?.let { throw it }
        }

        val wspdir = File(Paths.get(setupData.testPath, "topdir", "wsp",
            "6e99f804-7bb6-435a-9dce-53d9c6d33816").toString())
        assert(!wspdir.exists())
        lfs.entry(MServerPath("/ wsp 6e99f804-7bb6-435a-9dce-53d9c6d33816"))
            .makeDirectory()
            ?.let { throw it }
        assert(wspdir.exists())
    }

    @Test
    fun moveCopyTest() {
        val setupData = setupTest("fs.moveCopy")
        val lfs = LocalFS.get()

        val widStr = "6e99f804-7bb6-435a-9dce-53d9c6d33816"
        lfs.entry(MServerPath("/ wsp $widStr")).makeDirectory()?.let { throw it }
        val testFileName = makeTestFile(
            Paths.get(setupData.testPath, "topdir", "wsp", widStr).toString())
            .first

        lfs.entry(MServerPath("/ wsp $widStr $testFileName")).moveTo(MServerPath("/ wsp"))
        assert(File(Paths.get(setupData.testPath, "topdir", "wsp", testFileName).toString())
            .exists())

        val newFilePath = lfs.entry(MServerPath("/ wsp $testFileName"))
            .copyTo(MServerPath("/ wsp $widStr")).getOrThrow()
        val newFileLocalPath = lfs.convertToLocal(newFilePath)
        assert(File(newFileLocalPath.toString()).exists())
    }
}