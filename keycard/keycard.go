package keycard

import (
	"bytes"
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
	Level    int
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

		if eb.SignatureInfo[infoIndex].Optional {
			val, err := eb.Signatures[eb.SignatureInfo[infoIndex].Name]
			if err || len(val) < 1 {
				return false
			}

		}
	}

	return true
}

// GetSignature - get the specified signature
func (eb EntryBase) GetSignature(sigtype string) (string, error) {
	val, exists := eb.Signatures[sigtype]
	if exists {
		return val, nil
	}
	return val, errors.New("signature not found")
}

// MakeByteString converts the entry to a string of bytes to ensure that signatures are not
// invalidated by automatic line ending handling
func (eb EntryBase) MakeByteString(siglevel int) []byte {

	// Capacity is all possible field names + all actual signatures + hash fields
	lines := make([][]byte, 0, len(eb.FieldNames)+len(eb.Signatures)+2)
	if len(eb.Type) > 0 {
		lines = append(lines, []byte(eb.Type))
	}

	for i := range eb.FieldNames {
		if len(eb.Fields[eb.FieldNames[i]]) > 0 {
			lines = append(lines, []byte(eb.FieldNames[i]+":"+eb.Fields[eb.FieldNames[i]]))
		}
	}

	if siglevel < 0 || siglevel > len(eb.SignatureInfo) {
		siglevel = eb.SignatureInfo[len(eb.SignatureInfo)-1].Level
	}

	for i := 0; i < siglevel; i++ {
		if eb.SignatureInfo[i].Type == SigInfoHash {
			if len(eb.PrevHash) > 0 {
				lines = append(lines, []byte("Previous-Hash:"+eb.PrevHash))
			}
			if len(eb.Hash) > 0 {
				lines = append(lines, []byte("Hash:"+eb.Hash))
			}
			continue
		}

		if eb.SignatureInfo[i].Type != SigInfoSignature {
			panic("BUG: invalid signature info type in EntryBase.MakeByteString")
		}

		val, ok := eb.Signatures[eb.SignatureInfo[i].Name]
		if ok && len(val) > 0 {
			lines = append(lines, []byte(eb.SignatureInfo[i].Name+"-Signature:"+val))
		}

	}

	return bytes.Join(lines, []byte("\r\n"))
}
