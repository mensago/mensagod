package keznacl

import org.junit.jupiter.api.Test
import java.io.File
import java.nio.file.Paths
import kotlin.test.assertEquals

class HashTest {

    @Test
    fun testHashSupport() {
        assert(isSupportedAlgorithm("BLAKE2B-256"))
        assert(isSupportedHash("BLAKE2B-256"))
        val hashSupport = getSupportedHashAlgorithms()
        assertEquals(2, hashSupport.size)
        assertEquals(CryptoType.BLAKE2B_256, hashSupport[0])
        assertEquals(CryptoType.SHA_256, hashSupport[1])

        assertEquals(CryptoType.BLAKE2B_256, getPreferredHashAlgorithm())
    }

    @Test
    fun testBlake2B() {
        val expectedBlake =
            Hash.fromString("BLAKE2B-256:?*e?y<{rF)B`7<5U8?bXQhNic6W4lmGlN}~Mu}la")!!
        assertEquals(expectedBlake.value, blake2Hash("aaaaaaaa".toByteArray()).getOrThrow().value)

        assertEquals(
            expectedBlake.value, hash("aaaaaaaa".toByteArray(), CryptoType.BLAKE2B_256)
                .getOrThrow().value
        )
    }

    @Test
    fun testSHA256() {
        val expectedSHA =
            Hash.fromString("SHA-256:A3Wp)6`}|qqweQl!=L|-R>C51(W!W+B%4_+&b=VC")!!
        assertEquals(expectedSHA.value, sha256Hash("aaaaaaaa".toByteArray()).getOrThrow().value)

        assertEquals(
            expectedSHA.value, hash("aaaaaaaa".toByteArray(), CryptoType.SHA_256)
                .getOrThrow().value
        )
    }

    @Test
    fun testCheck() {
        val key = SecretKey.fromString("XSALSA20:Z%_Is*V6uc!_+QIG5F`UJ*cLYoO`=58RCuAk-`Bq")
            .getOrThrow()
        // The call to toHash() is for lint removal, not necessity. :)
        val hash = key.getHash().getOrThrow().toHash()!!
        assert(hash.check(key.key.toByteArray()).getOrThrow())
    }

    @Test
    fun testHashFile() {
        val testPath = Paths.get("build", "testfiles", "testHashFile")
            .toAbsolutePath()
            .toString()

        val testDir = File(testPath)
        if (!testDir.exists())
            testDir.mkdirs()

        val testdata = "0".repeat(10_000).encodeToByteArray()
        val startHash = hash(testdata).getOrThrow()

        val testFile = Paths.get(testDir.path, "fileToHash.txt").toFile()
        testFile.createNewFile()
        testFile.outputStream().write(testdata)

        val fileHash = hashFile(testFile.path).getOrThrow()
        assertEquals(startHash, fileHash)
    }
}
