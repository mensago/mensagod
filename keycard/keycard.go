package keycard

import (
	"errors"
	"strings"

	"github.com/darkwyrm/b85"
)

// AlgoString encapsulates a Base85-encoded binary string and its associated algorithm.
// Algorithms are expected to utilize capital letters, dashes, and numbers and be no more than
// 16 characters, not including the colon separator.
// Example: ED25519:p;XXU0XF#UO^}vKbC-wS(#5W6=OEIFmR2z`rS1j+
type AlgoString struct {
	Prefix string
	Data   string
}

// Set assigns an AlgoString-formatted string to the object
func (as AlgoString) Set(data string) error {
	if len(data) < 1 {
		as.Prefix = ""
		as.Data = ""
		return nil
	}

	parts := strings.SplitN(data, ":", 1)
	if len(parts) != 2 {
		return errors.New("bad string format")
	}
	as.Prefix = parts[0]
	as.Data = parts[1]

	return nil
}

// SetBytes initializes the AlgoString from an array of bytes
func (as AlgoString) SetBytes(data []byte) error {
	return as.Set(string(data))
}

// AsBytes returns the AlgoString as a byte array
func (as AlgoString) AsBytes() []byte {
	return []byte(as.Prefix + ":" + as.Data)
}

// AsString returns the AlgoString as a complete string
func (as AlgoString) AsString() string {
	return as.Prefix + ":" + as.Data
}

// IsValid returns true if the object contains valid data
func (as AlgoString) IsValid() bool {
	return (len(as.Prefix) > 0 && len(as.Data) > 0)
}

// RawData returns the raw data held in the string
func (as AlgoString) RawData() ([]byte, error) {
	return b85.Decode(as.Data)
}

// MakeEmpty clears the AlgoString's internal data
func (as AlgoString) MakeEmpty() {
	as.Prefix = ""
	as.Data = ""
}

// SigInfo contains descriptive information about the signatures for an entry. The Level property
// indicates order. For example, a signature with a level of 2 is attached to the entry after a
// level 1 signature.
type SigInfo struct {
	Name     string
	Level    string
	Type     uint8
	Optional bool
}

// EntryBase contains the common functionality for keycard entries
type EntryBase struct {
	Type           string
	Fields         map[string]string
	FieldNames     []string
	RequiredFields []string
	Signatures     map[string]string
	SignatureInfo  []SigInfo
	PrevHash       string
	Hash           string
}

// SigInfoHash - signature field is a hash
const SigInfoHash uint8 = 1

// SigInfoSignature - signature field is a cryptographic signature
const SigInfoSignature uint8 = 2

// IsCompliant returns true if the object meets spec compliance (required fields, etc.)
func (eb EntryBase) IsCompliant() bool {
	if eb.Type != "User" && eb.Type != "Organization" {
		return false
	}

	// Field compliance
	for field := range eb.RequiredFields {
		_, err := eb.Fields[eb.RequiredFields[field]]
		if err {
			return false
		}
	}

	// Signature compliance
	for infoIndex := range eb.SignatureInfo {
		if eb.SignatureInfo[infoIndex].Type == SigInfoHash {
			if len(eb.Hash) < 1 {
				return false
			}
			continue
		}

		if eb.SignatureInfo[infoIndex].Type != SigInfoSignature {
			return false
		}

	}

	// TODO: Finish implementation

	return true
}
