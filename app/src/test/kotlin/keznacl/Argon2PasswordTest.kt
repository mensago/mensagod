package keznacl

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class Argon2PasswordTest {

    private val weakTestHash = "\$argon2id\$v=19\$m=16384,t=1,p=1\$z48dw25lKtFmfLw6HTvR/g" +
        "\$TSXxBPLhZ1U2B+mBxOyw63WlwpUpwpfihRTEzTMfa44"
    private val weak2iHash = "\$argon2i\$v=19\$m=16384,t=1,p=1\$86jbEKB3WO0Nr8okRL9/MA" +
            "\$X0J81SApJRz44CX791lme+mfH8hy3NUMGFDOfZdIlak"
    private val weak2dHash = "\$argon2d\$v=19\$m=16384,t=1,p=1\$/0l+lSUhmlySJtm3Xg54gw" +
            "\$GX+3qldzdTISDoB3TKtjhXD2S5jgFbkhbzU7FLdqslc"

    @Test
    fun basicTests() {
        val hasher = Argon2idPassword()
        hasher.updateHash("MyS3cretPassw*rd").getOrThrow()
        assert(hasher.verify("MyS3cretPassw*rd"))
    }

    @Test
    fun passwordSync() {
        val firstHasher = Argon2idPassword()
        firstHasher.run {
            iterations = 1
            memory = 16384
            threads = 1
        }
        firstHasher.updateHash("MyS3cretPassw*rd")

        val secondHasher = Argon2idPassword()
        secondHasher.run {
            iterations = 1
            memory = 16384
            threads = 1
            salt = firstHasher.salt
        }
        secondHasher.updateHash("MyS3cretPassw*rd")
        assertEquals(firstHasher.hash, secondHasher.hash)
    }

    @Test
    fun setFromHash() {
        val hasher = argonPassFromHash(weakTestHash).getOrThrow()
        assertEquals(weakTestHash, hasher.hash)
        assertEquals("z48dw25lKtFmfLw6HTvR/g", hasher.salt)
        assertEquals("m=16384,t=1,p=1", hasher.parameters)
        assertEquals(1, hasher.iterations)
        assertEquals(16384, hasher.memory)
        assertEquals(1, hasher.threads)
        assertEquals(19, hasher.version)
    }

    @Test
    fun setFromInfo() {
        val info = PasswordInfo("ARGON2ID",
            "z48dw25lKtFmfLw6HTvR/g",
            "m=16384,t=1,p=2"
        )
        val hasher = passhasherForInfo(info).getOrThrow() as Argon2idPassword
        assertEquals(16384, hasher.memory)
        assertEquals(1, hasher.iterations)
        assertEquals(2, hasher.threads)

        assert(passhasherForInfo(PasswordInfo("BADALGO")).isFailure)
    }

    @Test
    fun setStrength() {
        val hasher = Argon2idPassword()
        hasher.run {
            iterations = 5
            memory = 16384
            threads = 2
            setStrength(HashStrength.Basic)
        }
        assertEquals(0x100_000, hasher.memory)
        assertEquals(10, hasher.iterations)
        assertEquals(4, hasher.threads)
    }

    @Test
    fun validateInfo() {
        assertNull(validatePasswordInfo(PasswordInfo("ARGON2ID",
            "z48dw25lKtFmfLw6HTvR/g",
            "m=16384,t=1,p=1"
        )))

        assertNotNull(validatePasswordInfo(PasswordInfo("BADALGO",
            "z48dw25lKtFmfLw6HTvR/g",
            "m=16384,t=1,p=1"
        )))

        assertNotNull(validatePasswordInfo(PasswordInfo("ARGON2ID",
            "",
            "m=16384,t=1,p=1"
        )))

        assertNotNull(validatePasswordInfo(PasswordInfo("ARGON2ID",
            "z48dw25lKtFmfLw6HTvR/g",
            ""
        )))

        assertNotNull(validatePasswordInfo(PasswordInfo("ARGON2ID",
            "z48dw25lKtFmfLw6HTvR/g",
            "m=a,t=1,p=1"
        )))

        assertNotNull(validatePasswordInfo(PasswordInfo("ARGON2ID",
            "z48dw25lKtFmfLw6HTvR/g",
            "m=16384,t=a,p=1"
        )))

        assertNotNull(validatePasswordInfo(PasswordInfo("ARGON2ID",
            "z48dw25lKtFmfLw6HTvR/g",
            "m=16384,t=1,p=a"
        )))
    }

    @Test
    fun lintRemoval() {
        val ihasher = Argon2iPassword()
        ihasher.run {
            iterations = 1
            memory = 16384
            threads = 1
        }
        assertNull(ihasher.setFromHash(weak2iHash))

        val dhasher = Argon2dPassword()
        dhasher.run {
            iterations = 1
            memory = 16384
            threads = 1
        }
        assertNull(dhasher.setFromHash(weak2dHash))
    }
}