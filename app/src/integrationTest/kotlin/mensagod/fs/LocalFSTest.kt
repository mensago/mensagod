package mensagod.fs

import mensagod.MServerPath
import mensagod.setupTest
import org.junit.jupiter.api.Test
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

        // TODO: add error cases to makeDirectory test
    }
}