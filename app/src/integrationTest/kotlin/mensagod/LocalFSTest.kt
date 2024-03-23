package mensagod

import libkeycard.RandomID
import libmensago.MServerPath
import org.apache.commons.io.FileUtils
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import testsupport.ADMIN_PROFILE_DATA
import testsupport.makeTestFile
import testsupport.setupTest
import java.io.File
import java.nio.file.Paths

class LocalFSTest {

    @Test
    fun convertTest() {
        setupTest("fs.convertTest")
        val lfs = LocalFS.get()

        val converted = Paths.get(
            lfs.basePath.toString(), "wsp",
            "d8b6d06b-7728-4c43-bc08-85a0c645d260"
        ).toString()

        assertEquals(
            converted, lfs.convertToLocal(
                MServerPath("/ wsp d8b6d06b-7728-4c43-bc08-85a0c645d260")
            ).toString()
        )
    }

    @Test
    fun listTest() {
        val setupData = setupTest("fs.list")
        val one = "11111111-1111-1111-1111-111111111111"
        val two = "22222222-2222-2222-2222-222222222222"
        val three = "33333333-3333-3333-3333-333333333333"

        val rootdir = Paths.get(setupData.testPath, "topdir")
        val oneInfo = makeTestFile(
            rootdir.toString(),
            "1000000.1024.$one",
            1024
        )
        val twoInfo = makeTestFile(
            rootdir.toString(),
            "1000100.1024.$two",
            1024
        )
        val threeInfo = makeTestFile(
            rootdir.toString(),
            "1000200.1024.$three",
            1024
        )

        val rootHandle = MServerPath().toHandle()

        val files = rootHandle.list(true).getOrThrow()
        assertEquals(3, files.size)
        assertEquals(oneInfo.first, files[0])
        assertEquals(twoInfo.first, files[1])
        assertEquals(threeInfo.first, files[2])

        val dirs = rootHandle.list(false).getOrThrow()
        assertEquals(4, dirs.size)
        assertEquals("keys", dirs[0])
        assertEquals("out", dirs[1])
        assertEquals("tmp", dirs[2])
        assertEquals("wsp", dirs[3])
    }

    @Test
    fun existsDeleteFileTest() {
        val setupData = setupTest("fs.deleteFile")
        val lfs = LocalFS.get()

        val topdir = Paths.get(setupData.testPath, "topdir").toString()
        val testFileInfo = makeTestFile(topdir)

        val deletePath = MServerPath("/ ${testFileInfo.first}")
        val handle = lfs.entry(deletePath)
        assert(handle.exists().getOrThrow())
        lfs.lock(deletePath)
        handle.delete()?.let { throw it }
        lfs.unlock(deletePath)
        assertFalse(handle.exists().getOrThrow())
    }

    @Test
    fun makeDirTest() {
        val setupData = setupTest("fs.makeDirectory")
        val lfs = LocalFS.get()

        assertThrows<FSFailureException> {
            lfs.entry(
                MServerPath(
                    "/ wsp 6e99f804-7bb6-435a-9dce-53d9c6d33816 5769bf90-aeb2-46b1-9bc5-4809d55991df"
                )
            )
                .makeDirectory()
                ?.let { throw it }
        }

        val wspdir = File(
            Paths.get(
                setupData.testPath, "topdir", "wsp",
                "6e99f804-7bb6-435a-9dce-53d9c6d33816"
            ).toString()
        )
        assert(!wspdir.exists())
        lfs.entry(MServerPath("/ wsp 6e99f804-7bb6-435a-9dce-53d9c6d33816"))
            .makeDirectory()
            ?.let { throw it }
        assert(wspdir.exists())
    }

    @Test
    fun makeTempTest() {
        setupTest("fs.makeTempFile")

        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        val lfs = LocalFS.get()
        val tempHandle = lfs.makeTempFile(adminWID, 4096).getOrThrow()
        FileUtils.touch(tempHandle.getFile())
    }

    @Test
    fun moveCopyTest() {
        val setupData = setupTest("fs.moveCopy")
        val lfs = LocalFS.get()

        val widStr = "6e99f804-7bb6-435a-9dce-53d9c6d33816"
        lfs.entry(MServerPath("/ wsp $widStr")).makeDirectory()?.let { throw it }
        val testFileName = makeTestFile(
            Paths.get(setupData.testPath, "topdir", "wsp", widStr).toString()
        )
            .first

        val movedEntry = lfs.entry(MServerPath("/ wsp $widStr $testFileName"))
        movedEntry.moveTo(MServerPath("/ wsp"))?.let { throw it }
        assert(
            File(Paths.get(setupData.testPath, "topdir", "wsp", testFileName).toString())
                .exists()
        )
        assertEquals("/ wsp $testFileName", movedEntry.path.toString())

        val newFilePath = lfs.entry(MServerPath("/ wsp $testFileName"))
            .copyTo(MServerPath("/ wsp $widStr")).getOrThrow()
        val newFileLocalPath = lfs.convertToLocal(newFilePath)
        assert(File(newFileLocalPath.toString()).exists())
    }
}