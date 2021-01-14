package encryption

// This module creates some classes which make working with Twisted Edwards Curve encryption
// a lot less difficult/confusing

// CryptoKey is a baseline interface to the different kinds of keys defined in this module
type CryptoKey interface {
	GetID() string
	GetEncryptionType() string
	GetType() string
}
