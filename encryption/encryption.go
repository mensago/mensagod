package encryption

import (
	"crypto/ed25519"
	"errors"

	"github.com/darkwyrm/anselusd/cryptostring"
	"github.com/darkwyrm/b85"
	"golang.org/x/crypto/blake2b"
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

// KeyPair defines an asymmetric encryption keypair
type KeyPair struct {
	PublicHash     string
	PrivateHash    string
	encryptionType string
	keyType        string
	pubkey         cryptostring.CryptoString
	privkey        cryptostring.CryptoString
}

// SigningPair defines an asymmetric signing keypair
type SigningPair struct {
	PublicHash     string
	PrivateHash    string
	encryptionType string
	keyType        string
	pubkey         cryptostring.CryptoString
	privkey        cryptostring.CryptoString
}
