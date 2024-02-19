package keznacl

import com.iwebpp.crypto.TweetNacl
import com.iwebpp.crypto.TweetNaclFast
import ove.crypto.digest.Blake2b
import java.security.GeneralSecurityException


class SealedBox {
    private val cryptoBoxNonceBytes = 24
    private val cryptoBoxPublicKeyBytes = 32
    private val cryptoBoxMacBytes = 16
    private val cryptoBoxSealBytes = cryptoBoxPublicKeyBytes + cryptoBoxMacBytes

    //  libsodium
    //  int crypto_box_seal(unsigned char *c, const unsigned char *m,
    //            unsigned long long mlen, const unsigned char *pk);
    /**
     * Encrypt in  a sealed box
     *
     * @param clearText clear text
     * @param receiverPubKey receiver public key
     * @return encrypted message or GeneralSecurityException
     */
    fun cryptoBoxSeal(clearText: ByteArray, receiverPubKey: ByteArray): Result<ByteArray> {

        val ephkeypair = TweetNaclFast.Box.keyPair()
        val nonce = cryptoBoxSealNonce(ephkeypair.publicKey, receiverPubKey) ?:
            return Result.failure(ProgramException("Nonce generation failure"))
        val box = TweetNacl.Box(receiverPubKey, ephkeypair.secretKey)
        val ciphertext = box.box(clearText, nonce) ?:
            return Result.failure(GeneralSecurityException("NaCl error: couldn't create box"))

        val sealedbox = ByteArray(ciphertext.size + cryptoBoxPublicKeyBytes)
        val ephpubkey: ByteArray = ephkeypair.publicKey
        for (i in 0 until cryptoBoxPublicKeyBytes)
            sealedbox[i] = ephpubkey[i]
        for (i in ciphertext.indices)
            sealedbox[i + cryptoBoxPublicKeyBytes] = ciphertext[i]
        return Result.success(sealedbox)
    }
    //  libsodium:
    //      int
    //      crypto_box_seal_open(unsigned char *m, const unsigned char *c,
    //                           unsigned long long clen,
    //                           const unsigned char *pk, const unsigned char *sk)
    /**
     * Decrypt a sealed box
     *
     * @param cipherText ciphertext
     * @param pubKey receiver public key
     * @param privKey receiver private key
     * @return decrypted message or GeneralSecurityException
     */
    fun cryptoBoxSealOpen(cipherText: ByteArray, pubKey: ByteArray, privKey: ByteArray): Result<ByteArray> {
        if (cipherText.size < cryptoBoxSealBytes) return Result.failure(BadValueException("Ciphertext too short"))

        val pksender = cipherText.copyOfRange(0, cryptoBoxPublicKeyBytes)
        val ciphertextwithmac = cipherText.copyOfRange(cryptoBoxPublicKeyBytes, cipherText.size)
        val nonce = cryptoBoxSealNonce(pksender, pubKey) ?:
            return Result.failure(ProgramException("Nonce generation failure"))
        val box: TweetNacl.Box = TweetNacl.Box(pksender, privKey)

        val result = box.open(ciphertextwithmac, nonce)
        return if (result != null) Result.success(result)
            else Result.failure(GeneralSecurityException("NaCl error: Could not open box"))
    }

    /**
     * hash the combination of senderpk + mypk into nonce using blake2b hash
     * @param senderPubKey the sender's public key
     * @param recipPubKey the recipient's public key
     * @return the nonce computed using Blake2b generic hash or null if the hash function failed
     */
    private fun cryptoBoxSealNonce(senderPubKey: ByteArray, recipPubKey: ByteArray): ByteArray? {
        // C source ported from libsodium
        //      crypto_generichash_state st;
        //
        //      crypto_generichash_init(&st, NULL, 0U, crypto_box_NONCEBYTES);
        //      crypto_generichash_update(&st, pk1, crypto_box_PUBLICKEYBYTES);
        //      crypto_generichash_update(&st, pk2, crypto_box_PUBLICKEYBYTES);
        //      crypto_generichash_final(&st, nonce, crypto_box_NONCEBYTES);
        //
        //      return 0;

        val blake2b = Blake2b.Digest.newInstance(cryptoBoxNonceBytes)
        blake2b.update(senderPubKey, 0, senderPubKey.size)
        blake2b.update(recipPubKey, 0, recipPubKey.size)
        val nonce = blake2b.digest()

        return if (nonce.size == cryptoBoxNonceBytes) nonce else null
    }
}
