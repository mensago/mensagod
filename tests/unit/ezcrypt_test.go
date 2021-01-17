package anselusd

import (
	"fmt"
	"testing"

	"github.com/darkwyrm/anselusd/cryptostring"
	"github.com/darkwyrm/anselusd/ezcrypt"
)

func TestEZCryptEncryptDecrypt(t *testing.T) {
	// def test_encryptionpair_encrypt_decrypt():
	// '''Test the encryption and decryption code for the EncryptionPair class'''

	// public_key = CryptoString(r"CURVE25519:(B2XX5|<+lOSR>_0mQ=KX4o<aOvXe6M`Z5ldINd`")
	// private_key = CryptoString(r"CURVE25519:(Rj5)mmd1|YqlLCUP0vE;YZ#o;tJxtlAIzmPD7b&")
	// kp = encryption.EncryptionPair(public_key, private_key)

	// test_data = 'This is some encryption test data'
	// estatus = kp.encrypt(test_data.encode())
	// assert not estatus.error(), 'test_encryptionpair_encrypt_decrypt: error encrypting test data'

	// dstatus = kp.decrypt(estatus['data'])
	// assert not dstatus.error(), 'test_encryptionpair_encrypt_decrypt: error decrypting test data'
	// assert dstatus['data'].decode() == test_data, 'decoded data mismatch'

	pubkey := cryptostring.New("CURVE25519:(B2XX5|<+lOSR>_0mQ=KX4o<aOvXe6M`Z5ldINd`")
	privkey := cryptostring.New("CURVE25519:(Rj5)mmd1|YqlLCUP0vE;YZ#o;tJxtlAIzmPD7b&")
	keypair := ezcrypt.NewEncryptionPair(pubkey, privkey)

	testData := "This is some encryption test data"
	encryptedData, err := keypair.Encrypt([]byte(testData))
	fmt.Print(encryptedData)
	if err != nil || encryptedData == "" {
		t.Fatal("EncryptedPair.Encrypt() failed")
	}

	decryptedRaw, err := keypair.Decrypt(encryptedData)
	if err != nil || decryptedRaw == nil {
		t.Fatal("EncryptedPair.Decrypt() failed")
	}

	if string(decryptedRaw) != testData {
		t.Fatal("EncryptedPair decrypted data mismatch")
	}

}
