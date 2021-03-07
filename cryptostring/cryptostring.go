package cryptostring

import (
	"errors"
	"regexp"
	"strings"

	"github.com/darkwyrm/b85"
)

// This module contains the Go implementation of CryptoString. It is very similar to the
// implementation in PyMensago, but also includes some special sauce to make interaction with
// Go's libsodium API, which is less than ideal.

// ErrUnsupportedAlgorithm is to be used if a function which leverages this module does not
// support the algorithm passed to it
var ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")

// CryptoString is a compact way of handling hashes and cryptographic keys such that (1) the
// algorithm used is obvious and (2) the data is encoded as text. The RFC 1924 variant of Base85
// encoding is used because it is more compact than Base64 and friendly to source code. The format
// looks like this: ALGORITHM:xxxxxxxxxxxxxxxxxxxx, where ALGORITHM is the name of the algorithm
// and the Xs represent the Base85-encoded data. The prefix is limited to 16 characters including
// the colon separator. Only capital ASCII letters, numbers, and dashes may be used in the prefix.
type CryptoString struct {
	Prefix string
	Data   string
}

// New is just syntactic sugar for generating a quickie CryptoString from a string
func New(cstring string) CryptoString {
	var out CryptoString
	out.Set(cstring)
	return out
}

// Set takes a CryptoString-formatted string and sets the object to it.
func (cs *CryptoString) Set(cstring string) error {
	cs.Prefix = ""
	cs.Data = ""

	// Data checks

	pattern := regexp.MustCompile("^[A-Z0-9-]{1,15}:")
	if !pattern.MatchString(cstring) {
		return errors.New("bad data given")
	}

	parts := strings.SplitN(cstring, ":", 2)
	if len(parts) != 2 || len(parts[1]) < 1 {
		return errors.New("crypto data missing")
	}

	_, err := b85.Decode(parts[1])
	if err != nil {
		return errors.New("base85 decoding error")
	}

	cs.Prefix = parts[0]
	cs.Data = parts[1]
	return nil
}

// AsString returns the state of the object as a CryptoString-formatted string
func (cs *CryptoString) AsString() string {
	return cs.Prefix + ":" + cs.Data
}

// RawData returns the data of the object as a series of bytes. In the event of an error, nil is
// returned
func (cs *CryptoString) RawData() []byte {
	out, err := b85.Decode(cs.Data)
	if err != nil {
		return nil
	}
	return out
}

// AsBytes returns the CryptoString as a byte array
func (cs *CryptoString) AsBytes() []byte {
	return []byte(cs.Prefix + ":" + cs.Data)
}

// MakeEmpty returns the object to an uninitialized state
func (cs *CryptoString) MakeEmpty() {
	cs.Prefix = ""
	cs.Data = ""
}

// IsValid checks the internal data and returns True if it is valid
func (cs *CryptoString) IsValid() bool {
	pattern := regexp.MustCompile("^[A-Z0-9-]{1,15}")
	if !pattern.MatchString(cs.Prefix) {
		return false
	}

	if len(cs.Data) < 1 {
		return false
	}

	_, err := b85.Decode(cs.Data)
	if err != nil {
		return false
	}

	return true
}
