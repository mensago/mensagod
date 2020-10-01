package keycard

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/darkwyrm/b85"
	"golang.org/x/crypto/nacl/sign"
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

// Save saves the entry to disk
func (eb EntryBase) Save(path string, clobber bool) error {
	if len(path) < 1 {
		return errors.New("empty path")
	}

	_, err := os.Stat(path)
	if !os.IsNotExist(err) && !clobber {
		return errors.New("file exists")
	}

	return ioutil.WriteFile(path, eb.MakeByteString(-1), 0644)
}

// SetField sets an entry field to the specified value.
func (eb EntryBase) SetField(fieldName string, fieldValue string) error {
	if len(fieldName) < 1 {
		return errors.New("empty field name")
	}
	eb.Fields[fieldName] = fieldValue

	// Any kind of editing invalidates the signatures and hashes
	eb.Signatures = make(map[string]string)
	return nil
}

// SetFields sets multiple entry fields
func (eb EntryBase) SetFields(fields map[string]string) {
	// Any kind of editing invalidates the signatures and hashes. Unlike SetField, we clear the
	// signature fields first because it's possible to set everything in the entry with this
	// method, so the signatures can be valid after the call finishes if they are set by the
	// caller.
	eb.Signatures = make(map[string]string)

	for k, v := range fields {
		eb.Fields[k] = v
	}
}

// Set initializes the entry from a bytestring
func (eb EntryBase) Set(data []byte) error {
	if len(data) < 1 {
		return errors.New("empty byte field")
	}

	lines := strings.Split(string(data), "\r\n")

	for linenum, rawline := range lines {
		line := strings.TrimSpace(rawline)
		parts := strings.SplitN(line, ":", 1)

		if len(parts) != 2 {
			return fmt.Errorf("bad data near line %d", linenum)
		}

		if parts[0] == "Type" {
			if parts[1] != eb.Type {
				return fmt.Errorf("Can't use %s data on %s entries", parts[1], eb.Type)
			}
		} else if strings.HasSuffix(parts[0], "Signature") {
			sigparts := strings.SplitN(parts[0], "-", 1)
			validSig := false
			for _, sigitem := range eb.SignatureInfo {
				if sigparts[0] == sigitem.Name {
					validSig = true
					break
				}
			}
			if !validSig {
				return fmt.Errorf("%s is not a valid signature type", sigparts[0])
			}
			eb.Signatures[sigparts[0]] = sigparts[1]
		} else {
			eb.Fields[parts[0]] = parts[1]
		}
	}

	return nil
}

// SetExpiration enables custom expiration dates, the standard being 90 days for user entries and
// 1 year for organizations.
func (eb EntryBase) SetExpiration(numdays uint16) error {
	if numdays < 0 {
		if eb.Type == "Organization" {
			numdays = 365
		} else if eb.Type == "User" {
			numdays = 90
		} else {
			return errors.New("unsupported keycard type")
		}
	}

	// An expiration date can be no longer than three years
	if numdays > 1095 {
		numdays = 1095
	}

	eb.Fields["Expiration"] = time.Now().AddDate(0, 0, int(numdays)).Format("%Y%m%d")

	return nil
}

// Sign cryptographically signs an entry. The supported types and expected order of the signature
// is defined by subclasses using the SigInfo instances in the object's SignatureInfo property.
// Adding a particular signature causes those that must follow it to be cleared. The EntryBase's
// cryptographic hash counts as a signature in this matter. Thus, if an Organization signature is
// added to the entry, the instance's hash and User signatures are both cleared.
func (eb EntryBase) Sign(signingKey AlgoString, sigtype string) error {
	if !signingKey.IsValid() {
		return errors.New("bad signing key")
	}

	if signingKey.Prefix != "ED25519" {
		return errors.New("unsupported signing algorithm")
	}

	sigtypeOK := false
	sigtypeIndex := -1
	for i := range eb.SignatureInfo {
		if sigtype == eb.SignatureInfo[i].Name {
			sigtypeOK = true
			sigtypeIndex = i
		}

		// Once we have found the index of the signature, it and all following signatures must be
		// cleared because they will no longer be valid
		if sigtypeOK {
			eb.Signatures[eb.SignatureInfo[i].Name] = ""
		}
	}

	if !sigtypeOK {
		return errors.New("bad signature type")
	}

	signkeyDecoded, err := signingKey.RawData()
	if err != nil {
		return err
	}

	var signkeyArray [64]byte
	signKeyAdapter := signkeyArray[0:64]
	copy(signKeyAdapter, signkeyDecoded)

	signature := sign.Sign(nil, eb.MakeByteString(sigtypeIndex+1), &signkeyArray)
	eb.Signatures[sigtype] = "ED25519:" + b85.Encode(signature)

	return nil
}
