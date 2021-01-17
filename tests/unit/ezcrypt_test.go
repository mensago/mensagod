package anselusd

import (
	"testing"

	"github.com/darkwyrm/anselusd/cryptostring"
	"github.com/darkwyrm/anselusd/ezcrypt"
)

func TestEZCryptEncryptDecrypt(t *testing.T) {
	pubkey := cryptostring.New("CURVE25519:(B2XX5|<+lOSR>_0mQ=KX4o<aOvXe6M`Z5ldINd`")
	privkey := cryptostring.New("CURVE25519:(Rj5)mmd1|YqlLCUP0vE;YZ#o;tJxtlAIzmPD7b&")
	keypair := ezcrypt.NewEncryptionPair(pubkey, privkey)

	testData := "This is some encryption test data"
	encryptedData, err := keypair.Encrypt([]byte(testData))
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

func TestEZCryptSignVerify(t *testing.T) {
	verkey := cryptostring.New("ED25519:PnY~pK2|;AYO#1Z;B%T$2}E$^kIpL=>>VzfMKsDx")
	signkey := cryptostring.New("ED25519:{^A@`5N*T%5ybCU%be892x6%*Rb2rnYd=SGeO4jF")
	keypair := ezcrypt.NewSigningPair(verkey, signkey)

	testData := "This is some signing test data"

	signature, err := keypair.Sign([]byte(testData))
	if err != nil || !signature.IsValid() {
		t.Fatal("SigningPair.Sign() failed")
	}

	verified, err := keypair.Verify([]byte(testData), signature)
	if err != nil || !verified {
		t.Fatal("SigningPair.Verify() failed")
	}
}
