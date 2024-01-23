package mensagod.fs

import keznacl.BadValueException
import mensagod.MServerPath
import mensagod.setupTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.io.File
import java.nio.file.Paths

class LocalFSTest {

    @Test
    fun makeDirTest() {
        val testdir = setupTest("fs.makeDirectory")
        val lfs = LocalFS.get()

        val wspdir = File(Paths.get(testdir, "topdir", "wsp").toString())
        assert(!wspdir.exists())
        lfs.makeDirectory(MServerPath("/ wsp"))
        assert(wspdir.exists())

        assertThrows<BadValueException> {
            lfs.makeDirectory(MServerPath("/ wsp 6e99f804-7bb6-435a-9dce-53d9c6d33816"))
        }
        // TODO: add error cases to makeDirectory test
    }
}