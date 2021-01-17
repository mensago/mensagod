package ezcrypt

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"

	"github.com/darkwyrm/anselusd/cryptostring"
	"github.com/darkwyrm/b85"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/nacl/box"
)

// This module creates some classes which make working with Twisted Edwards Curve encryption
// a lot less difficult/confusing

// CryptoKey is a baseline interface to the different kinds of keys defined in this module
type CryptoKey interface {
	GetEncryptionType() string
	GetType() string
}

// VerificationKey is an object to represent just a verification key, not a key pair
type VerificationKey struct {
	PublicHash     string
	encryptionType string
	keyType        string
	key            cryptostring.CryptoString
}

// NewVerificationKey creates a new verification key from a CryptoString
func NewVerificationKey(key cryptostring.CryptoString) *VerificationKey {
	var newkey VerificationKey
	if newkey.Set(key) != nil {
		return nil
	}

	return &newkey
}

// GetEncryptionType returns the algorithm used by the key
func (vkey VerificationKey) GetEncryptionType() string {
	return vkey.encryptionType
}

// GetType returns the type of key -- asymmetric or symmetric
func (vkey VerificationKey) GetType() string {
	return vkey.keyType
}

// Verify uses the internal verification key with the passed data and signature and returns true
// if the signature has verified the data with that key.
func (vkey VerificationKey) Verify(data []byte, signature cryptostring.CryptoString) (bool, error) {
	if !signature.IsValid() {
		return false, errors.New("invalid signature")
	}

	if signature.Prefix != "ED25519" {
		return false, errors.New("signature uses unsupported signing algorithm")
	}
	digest := signature.RawData()
	if digest == nil {
		return false, errors.New("decoding error in signature")
	}

	verifyKeyDecoded := vkey.key.RawData()
	if verifyKeyDecoded == nil {
		return false, errors.New("decoding error in verification key")
	}

	verifyStatus := ed25519.Verify(verifyKeyDecoded, data, digest)

	return verifyStatus, nil
}

// Set assigns a CryptoString value to the key
func (vkey *VerificationKey) Set(key cryptostring.CryptoString) error {
	if key.Prefix != "ED25519" {
		return errors.New("unsupported signing algorithm")
	}
	vkey.key = key

	sum := blake2b.Sum256([]byte(vkey.key.AsString()))
	vkey.PublicHash = "BLAKE2B-256:" + b85.Encode(sum[:])

	return nil
}

// SigningPair defines an asymmetric signing EncryptionPair
type SigningPair struct {
	PublicHash     string
	PrivateHash    string
	encryptionType string
	keyType        string
	PublicKey      cryptostring.CryptoString
	PrivateKey     cryptostring.CryptoString
}

// NewSigningPair creates a new SigningPair object from two CryptoString objects
func NewSigningPair(pubkey cryptostring.CryptoString,
	privkey cryptostring.CryptoString) *SigningPair {
	var newpair SigningPair
	if newpair.Set(pubkey, privkey) != nil {
		return nil
	}

	return &newpair
}

// GetEncryptionType returns the algorithm used by the key
func (spair SigningPair) GetEncryptionType() string {
	return spair.encryptionType
}

// GetType returns the type of key -- asymmetric or symmetric
func (spair SigningPair) GetType() string {
	return spair.keyType
}

// Set assigns a pair of CryptoString values to the EncryptionPair
func (spair *SigningPair) Set(pubkey cryptostring.CryptoString,
	privkey cryptostring.CryptoString) error {

	if pubkey.Prefix != "ED25519" || privkey.Prefix != "ED25519" {
		return errors.New("unsupported signing algorithm")
	}
	spair.PublicKey = pubkey
	spair.PrivateKey = privkey

	sum := blake2b.Sum256([]byte(pubkey.AsString()))
	spair.PublicHash = "BLAKE2B-256:" + b85.Encode(sum[:])
	sum = blake2b.Sum256([]byte(privkey.AsString()))
	spair.PrivateHash = "BLAKE2B-256:" + b85.Encode(sum[:])

	return nil
}

// Generate initializes the object to a new key pair
func (spair SigningPair) Generate() error {
	verkey, signkey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	return spair.Set(cryptostring.New("ED25519:"+b85.Encode(verkey[:])),
		cryptostring.New("ED25519:"+b85.Encode(signkey.Seed())))
}

// Sign cryptographically signs a byte slice.
func (spair SigningPair) Sign(data []byte) (cryptostring.CryptoString, error) {
	var out cryptostring.CryptoString

	signkeyDecoded := spair.PrivateKey.RawData()
	if signkeyDecoded == nil {
		return out, errors.New("bad signing key")
	}

	// We bypass the nacl/sign module because it requires a 64-bit private key. We, however, pass
	// around the 32-bit ed25519 seeds used to generate the keys. Thus, we have to skip using
	// nacl.Sign() and go directly to the equivalent code in the ed25519 module.
	signKeyPriv := ed25519.NewKeyFromSeed(signkeyDecoded)
	signature := ed25519.Sign(signKeyPriv, data)
	out.Set("ED25519:" + b85.Encode(signature))

	return out, nil
}

// Verify uses the internal verification key with the passed data and signature and returns true
// if the signature has verified the data with that key.
func (spair SigningPair) Verify(data []byte, signature cryptostring.CryptoString) (bool, error) {
	if !signature.IsValid() {
		return false, errors.New("invalid signature")
	}

	if signature.Prefix != "ED25519" {
		return false, errors.New("signature uses unsupported signing algorithm")
	}
	digest := signature.RawData()
	if digest == nil {
		return false, errors.New("decoding error in signature")
	}

	verifyKeyDecoded := spair.PublicKey.RawData()
	if verifyKeyDecoded == nil {
		return false, errors.New("decoding error in verification key")
	}

	verifyStatus := ed25519.Verify(verifyKeyDecoded, data, digest)

	return verifyStatus, nil
}

// EncryptionPair defines an asymmetric encryption EncryptionPair
type EncryptionPair struct {
	PublicHash     string
	PrivateHash    string
	encryptionType string
	keyType        string
	PublicKey      cryptostring.CryptoString
	PrivateKey     cryptostring.CryptoString
}

// NewEncryptionPair creates a new EncryptionPair object from two CryptoString objects
func NewEncryptionPair(pubkey cryptostring.CryptoString, privkey cryptostring.CryptoString) *EncryptionPair {
	var newpair EncryptionPair

	// All parameter validation is handled in Set
	if newpair.Set(pubkey, privkey) != nil {
		return nil
	}

	return &newpair
}

// GetEncryptionType returns the algorithm used by the key
func (kpair EncryptionPair) GetEncryptionType() string {
	return kpair.encryptionType
}

// GetType returns the type of key -- asymmetric or symmetric
func (kpair EncryptionPair) GetType() string {
	return kpair.keyType
}

// Set assigns a pair of CryptoString values to the EncryptionPair
func (kpair *EncryptionPair) Set(pubkey cryptostring.CryptoString,
	privkey cryptostring.CryptoString) error {

	if pubkey.Prefix != "CURVE25519" || privkey.Prefix != "CURVE25519" {
		return errors.New("unsupported encryption algorithm")
	}
	kpair.PublicKey = pubkey
	kpair.PrivateKey = privkey

	sum := blake2b.Sum256([]byte(pubkey.AsString()))
	kpair.PublicHash = "BLAKE2B-256:" + b85.Encode(sum[:])
	sum = blake2b.Sum256([]byte(privkey.AsString()))
	kpair.PrivateHash = "BLAKE2B-256:" + b85.Encode(sum[:])

	return nil
}

// Generate initializes the object to a new key pair
func (kpair EncryptionPair) Generate() error {
	pubkey, privkey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	return kpair.Set(cryptostring.New("CURVE25519:"+b85.Encode(pubkey[:])),
		cryptostring.New("CURVE25519:"+b85.Encode(privkey[:])))
}

// Encrypt encrypts byte slice using the internal public key. It returns the resulting encrypted
// data as a Base85-encoded string that amounts to a CryptoString without the prefix.
func (kpair EncryptionPair) Encrypt(data []byte) (string, error) {
	if data == nil {
		return "", nil
	}

	pubKeyDecoded := kpair.PublicKey.RawData()
	if pubKeyDecoded == nil {
		return "", errors.New("decoding error in public key")
	}

	// This kind of stupid is why this class is even necessary
	var tempPtr [32]byte
	ptrAdapter := tempPtr[0:32]
	copy(ptrAdapter, pubKeyDecoded)

	encryptedData, err := box.SealAnonymous(nil, data, &tempPtr, rand.Reader)
	if err != nil {
		return "", err
	}

	return b85.Encode(encryptedData), nil
}

// Decrypt decrypts a string of encrypted data which is Base85 encoded using the internal private
// key.
func (kpair EncryptionPair) Decrypt(data string) ([]byte, error) {
	if data == "" {
		return nil, nil
	}

	pubKeyDecoded := kpair.PublicKey.RawData()
	if pubKeyDecoded == nil {
		return nil, errors.New("decoding error in public key")
	}
	var pubKeyPtr [32]byte

	ptrAdapter := pubKeyPtr[0:32]
	copy(ptrAdapter, pubKeyDecoded)

	privKeyDecoded := kpair.PrivateKey.RawData()
	if privKeyDecoded == nil {
		return nil, errors.New("decoding error in private key")
	}
	var privKeyPtr [32]byte

	ptrAdapter = privKeyPtr[0:32]
	copy(ptrAdapter, privKeyDecoded)

	decodedData, err := b85.Decode(data)
	if err != nil {
		return nil, err
	}

	decryptedData, ok := box.OpenAnonymous(nil, decodedData, &pubKeyPtr, &privKeyPtr)

	if ok {
		return decryptedData, nil
	}
	return nil, errors.New("decryption error")
}
