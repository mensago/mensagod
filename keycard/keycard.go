package keycard

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/darkwyrm/b85"
	"github.com/darkwyrm/gostringlist"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/sha3"
)

// EncodedString encapsulates a Base85-encoded binary string and its associated algorithm.
// Algorithms are expected to utilize capital letters, dashes, and numbers and be no more than
// 16 characters, not including the colon separator.
// Example: ED25519:p;XXU0XF#UO^}vKbC-wS(#5W6=OEIFmR2z`rS1j+
type EncodedString struct {
	Prefix string
	Data   string
}

// Set assigns an EncodedString-formatted string to the object
func (as *EncodedString) Set(data string) error {
	if len(data) < 1 {
		as.Prefix = ""
		as.Data = ""
		return nil
	}

	parts := strings.SplitN(data, ":", 2)
	if len(parts) != 2 {
		return errors.New("bad string format")
	}
	as.Prefix = parts[0]
	as.Data = parts[1]

	return nil
}

// SetBytes initializes the EncodedString from an array of bytes
func (as *EncodedString) SetBytes(data []byte) error {
	return as.Set(string(data))
}

// AsBytes returns the EncodedString as a byte array
func (as EncodedString) AsBytes() []byte {
	return []byte(as.Prefix + ":" + as.Data)
}

// AsString returns the EncodedString as a complete string
func (as EncodedString) AsString() string {
	return as.Prefix + ":" + as.Data
}

// IsValid returns true if the object contains valid data
func (as EncodedString) IsValid() bool {
	return (len(as.Prefix) > 0 && len(as.Data) > 0)
}

// RawData returns the raw data held in the string
func (as EncodedString) RawData() ([]byte, error) {
	return b85.Decode(as.Data)
}

// MakeEmpty clears the EncodedString's internal data
func (as *EncodedString) MakeEmpty() {
	as.Prefix = ""
	as.Data = ""
}

// KeyInfo describes the encryption and signing key fields for an Entry object
type KeyInfo struct {
	Name     string
	Type     string
	Optional bool
}

// SigInfo contains descriptive information about the signatures for an entry. The Level property
// indicates order. For example, a signature with a level of 2 is attached to the entry after a
// level 1 signature.
type SigInfo struct {
	Name     string
	Level    int
	Optional bool
	Type     uint8
}

// SigInfoHash - signature field is a hash
const SigInfoHash uint8 = 1

// SigInfoSignature - signature field is a cryptographic signature
const SigInfoSignature uint8 = 2

// SigInfoList is a specialized list container for SigInfo structure instances
type SigInfoList struct {
	Items []SigInfo
}

// Contains returns true if one of the SigInfo items has the specified name
func (sil SigInfoList) Contains(name string) bool {
	for _, item := range sil.Items {
		if item.Name == name {
			return true
		}
	}
	return false
}

// IndexOf returns the index of the item named and -1 if it doesn't exist
func (sil SigInfoList) IndexOf(name string) int {
	for i, item := range sil.Items {
		if item.Name == name {
			return i
		}
	}
	return -1
}

// GetItem returns the item matching the specified name or nil if it doesn't exist
func (sil SigInfoList) GetItem(name string) (bool, *SigInfo) {
	for _, item := range sil.Items {
		if item.Name == name {
			return true, &item
		}
	}
	var empty SigInfo
	return false, &empty
}

// Entry contains the common functionality for keycard entries
type Entry struct {
	Type           string
	Fields         map[string]string
	FieldNames     gostringlist.StringList
	RequiredFields gostringlist.StringList
	Signatures     map[string]string
	SignatureInfo  SigInfoList
	PrevHash       string
	Hash           string
	Keys           []KeyInfo
}

// IsDataCompliant checks only the data fields of the entry to ensure that they are valid
func (entry Entry) IsDataCompliant() bool {
	if entry.Type != "User" && entry.Type != "Organization" {
		return false
	}

	for _, reqField := range entry.RequiredFields.Items {
		strValue, ok := entry.Fields[reqField]
		if !ok || strValue != strings.TrimSpace(strValue) {
			return false
		}
	}

	// If a field exists, it may not be empty and may not be greater than 6144 bytes
	for _, fieldValue := range entry.Fields {
		if fieldValue == "" || len(fieldValue) > 6144 {
			return false
		}
	}

	var dataValid bool
	if entry.Type == "User" {
		dataValid, _ = entry.validateUserEntry()
	} else {
		dataValid, _ = entry.validateOrgEntry()
	}

	return dataValid
}

// IsCompliant returns true if the object meets spec compliance (required fields, etc.)
func (entry Entry) IsCompliant() bool {

	if !entry.IsDataCompliant() {
		return false
	}

	// Signature compliance
	for _, item := range entry.SignatureInfo.Items {
		if item.Type == SigInfoHash {
			if len(entry.Hash) < 1 {
				return false
			}
			continue
		}

		if item.Type != SigInfoSignature {
			return false
		}

		if !item.Optional {
			val, ok := entry.Signatures[item.Name]
			if !ok || len(val) < 1 {
				return false
			}

		}
	}

	return true
}

// IsExpired returns true if the entry has expired
func (entry Entry) IsExpired() bool {
	// TODO: Implement keycard::IsExpired()

	return true
}

// IsTimestampValid returns true if the timestamp for the entry is valid
func (entry Entry) IsTimestampValid() bool {
	// TODO: Implement keycard::IsTimestampValid()

	return false
}

// GetSignature - get the specified signature
func (entry Entry) GetSignature(sigtype string) (string, error) {
	val, exists := entry.Signatures[sigtype]
	if exists {
		return val, nil
	}
	return val, errors.New("signature not found")
}

// MakeByteString converts the entry to a string of bytes to ensure that signatures are not
// invalidated by automatic line ending handling
func (entry Entry) MakeByteString(siglevel int) []byte {

	// Capacity is all possible field names + all actual signatures + hash fields
	// lines := gostringlist.New()
	var lines gostringlist.StringList
	if len(entry.Type) > 0 {
		lines.Append("Type:" + entry.Type)
	}

	for _, fieldName := range entry.FieldNames.Items {
		if len(entry.Fields[fieldName]) > 0 {
			lines.Append(fieldName + ":" + entry.Fields[fieldName])
		}
	}

	if siglevel < 0 || siglevel > len(entry.SignatureInfo.Items) {
		siglevel = entry.SignatureInfo.Items[len(entry.SignatureInfo.Items)-1].Level
	}

	for i := 0; i < siglevel; i++ {
		if entry.SignatureInfo.Items[i].Type == SigInfoHash {
			if len(entry.PrevHash) > 0 {
				lines.Append("Previous-Hash:" + entry.PrevHash)
			}
			if len(entry.Hash) > 0 {
				lines.Append("Hash:" + entry.Hash)
			}
			continue
		}

		if entry.SignatureInfo.Items[i].Type != SigInfoSignature {
			panic("BUG: invalid signature info type in Entry.MakeByteString")
		}

		val, ok := entry.Signatures[entry.SignatureInfo.Items[i].Name]
		if ok && len(val) > 0 {
			lines.Append(entry.SignatureInfo.Items[i].Name + "-Signature:" + val)
		}

	}
	lines.Append("")
	return []byte(lines.Join("\r\n"))
}

// Save saves the entry to disk
func (entry Entry) Save(path string, clobber bool) error {
	if len(path) < 1 {
		return errors.New("empty path")
	}

	_, err := os.Stat(path)
	if !os.IsNotExist(err) && !clobber {
		return errors.New("file exists")
	}

	return ioutil.WriteFile(path, entry.MakeByteString(-1), 0644)
}

// SetField sets an entry field to the specified value.
func (entry *Entry) SetField(fieldName string, fieldValue string) error {
	if len(fieldName) < 1 {
		return errors.New("empty field name")
	}
	entry.Fields[fieldName] = fieldValue

	// Any kind of editing invalidates the signatures and hashes
	entry.Signatures = make(map[string]string)
	return nil
}

// SetFields sets multiple entry fields
func (entry *Entry) SetFields(fields map[string]string) {
	// Any kind of editing invalidates the signatures and hashes. Unlike SetField, we clear the
	// signature fields first because it's possible to set everything in the entry with this
	// method, so the signatures can be valid after the call finishes if they are set by the
	// caller.
	entry.Signatures = make(map[string]string)

	for k, v := range fields {
		entry.Fields[k] = v
	}
}

// Set initializes the entry from a bytestring
func (entry *Entry) Set(data []byte) error {
	// CAUTION: This function needs to be extra careful because it handles untrusted data

	if len(data) < 1 {
		return errors.New("empty byte field")
	}

	lines := strings.Split(string(data), "\r\n")

	stripHeader := false
	if entry.Type == "Organization" {
		if lines[0] != "----- BEGIN ORG ENTRY -----" ||
			lines[len(lines)-1] != "----- END ORG ENTRY -----" {
			return errors.New("bad entry header/footer")
		}
		stripHeader = true
	} else if entry.Type == "User" {
		if lines[0] != "----- BEGIN USER ENTRY -----" ||
			lines[len(lines)-1] != "----- END USER ENTRY -----" {
			return errors.New("bad entry header/footer")
		}
		stripHeader = true
	} else {
		return errors.New("bad entry type")
	}

	startLine := 0
	endLine := len(lines) - 1
	if stripHeader {
		startLine++
		endLine--
	}

	for linenum, rawline := range lines[startLine:endLine] {
		line := strings.TrimSpace(rawline)
		if len(line) < 1 {
			continue
		}
		parts := strings.SplitN(line, ":", 2)

		if len(parts) != 2 {
			return fmt.Errorf("bad data near line %d", linenum)
		}

		if parts[0] == "Type" {
			if parts[1] != entry.Type {
				return fmt.Errorf("Can't use %s data on %s entries", parts[1], entry.Type)
			}
		} else if strings.HasSuffix(parts[0], "Signature") {
			sigNameParts := strings.SplitN(parts[0], "-", 2)
			if !entry.SignatureInfo.Contains(sigNameParts[0]) {
				return fmt.Errorf("%s is not a valid signature type", sigNameParts[0])
			}

			entry.Signatures[sigNameParts[0]] = parts[1]
		} else {
			entry.Fields[parts[0]] = parts[1]
		}
	}

	return nil
}

// SetExpiration enables custom expiration dates, the standard being 90 days for user entries and
// 1 year for organizations.
func (entry *Entry) SetExpiration(numdays int16) error {
	if numdays < 0 {
		if entry.Type == "Organization" {
			numdays = 365
		} else if entry.Type == "User" {
			numdays = 90
		} else {
			return errors.New("unsupported keycard type")
		}
	}

	// An expiration date can be no longer than three years
	if numdays > 1095 {
		numdays = 1095
	}

	entry.Fields["Expiration"] = time.Now().AddDate(0, 0, int(numdays)).Format("%Y%m%d")

	return nil
}

// Sign cryptographically signs an entry. The supported types and expected order of the signature
// is defined by subclasses using the SigInfo instances in the object's SignatureInfo property.
// Adding a particular signature causes those that must follow it to be cleared. The Entry's
// cryptographic hash counts as a signature in this matter. Thus, if an Organization signature is
// added to the entry, the instance's hash and User signatures are both cleared.
func (entry *Entry) Sign(signingKey EncodedString, sigtype string) error {
	if !signingKey.IsValid() {
		return errors.New("bad signing key")
	}

	if signingKey.Prefix != "ED25519" {
		return errors.New("unsupported signing algorithm")
	}

	sigtypeOK := false
	sigtypeIndex := -1
	for i := range entry.SignatureInfo.Items {
		if sigtype == entry.SignatureInfo.Items[i].Name {
			sigtypeOK = true
			sigtypeIndex = i
		}

		// Once we have found the index of the signature, it and all following signatures must be
		// cleared because they will no longer be valid
		if sigtypeOK {
			entry.Signatures[entry.SignatureInfo.Items[i].Name] = ""
		}
	}

	if !sigtypeOK {
		return errors.New("bad signature type")
	}

	signkeyDecoded, err := signingKey.RawData()
	if err != nil {
		return err
	}

	// We bypass the nacl/sign module because it requires a 64-bit private key. We, however, pass
	// around the 32-bit ed25519 seeds used to generate the keys. Thus, we have to skip using
	// nacl.Sign() and go directly to the equivalent code in the ed25519 module.
	signKeyPriv := ed25519.NewKeyFromSeed(signkeyDecoded)
	signature := ed25519.Sign(signKeyPriv, entry.MakeByteString(sigtypeIndex+1))
	entry.Signatures[sigtype] = "ED25519:" + b85.Encode(signature)

	return nil
}

// GenerateHash generates a hash containing the expected signatures and the previous hash, if it
// exists. The supported hash algorithms are 'BLAKE3-256', 'BLAKE2B-256', 'SHA-256', and 'SHA3-256'.
func (entry *Entry) GenerateHash(algorithm string) error {
	validAlgorithm := false
	switch algorithm {
	case
		"BLAKE3-256",
		"BLAKE2B-256",
		"SHA-256",
		"SHA3-256":
		validAlgorithm = true
	}

	if !validAlgorithm {
		return errors.New("unsupported hashing algorithm")
	}

	hashLevel := -1
	for i := range entry.SignatureInfo.Items {
		if entry.SignatureInfo.Items[i].Type == SigInfoHash {
			hashLevel = entry.SignatureInfo.Items[i].Level
			break
		}
	}

	if hashLevel < 0 {
		panic("BUG: SignatureInfo missing hash entry")
	}

	switch algorithm {
	case "BLAKE3-256":
		sum := blake3.Sum256(entry.MakeByteString(hashLevel))
		entry.Hash = algorithm + ":" + b85.Encode(sum[:])
	case "BLAKE2B-256":
		sum := blake2b.Sum256(entry.MakeByteString(hashLevel))
		entry.Hash = algorithm + ":" + b85.Encode(sum[:])
	case "SHA256":
		sum := sha256.Sum256(entry.MakeByteString(hashLevel))
		entry.Hash = algorithm + ":" + b85.Encode(sum[:])
	case "SHA3-256":
		sum := sha3.Sum256(entry.MakeByteString(hashLevel))
		entry.Hash = algorithm + ":" + b85.Encode(sum[:])
	}

	return nil
}

// VerifySignature cryptographically verifies the entry against the key provided, given the
// specific signature to verify.
func (entry Entry) VerifySignature(verifyKey EncodedString, sigtype string) (bool, error) {

	if !verifyKey.IsValid() {
		return false, errors.New("bad verification key")
	}

	if verifyKey.Prefix != "ED25519" {
		return false, errors.New("unsupported signing algorithm")
	}

	if !entry.SignatureInfo.Contains(sigtype) {
		return false, fmt.Errorf("%s is not a valid signature type", sigtype)
	}

	infoValid, sigInfo := entry.SignatureInfo.GetItem(sigtype)
	if !infoValid {
		return false, errors.New("specified signature missing")
	}

	if entry.Signatures[sigtype] == "" {
		return false, errors.New("specified signature empty")
	}

	var sig EncodedString
	err := sig.Set(entry.Signatures[sigtype])
	if err != nil {
		return false, err
	}
	if sig.Prefix != "ED25519" {
		return false, errors.New("signature uses unsupported signing algorithm")
	}
	digest, err := sig.RawData()
	if err != nil {
		return false, errors.New("decoding error in signature")
	}

	verifyKeyDecoded, err := verifyKey.RawData()
	if err != nil {
		return false, err
	}

	verifyStatus := ed25519.Verify(verifyKeyDecoded, entry.MakeByteString(sigInfo.Level-1), digest)

	return verifyStatus, nil
}

// Chain creates a new Entry object with new keys and a custody signature. It requires the
// previous contact request signing key passed as an EncodedString. The new keys are returned with the
// string '.private' or '.public' appended to the key's field name, e.g.
// Primary-Encryption-Key.public.
//
// Note that a user's public encryption keys and an organization's alternate verification key are
// not required to be updated during entry rotation so that they can be rotated on a different
// schedule from the other keys.
func (entry *Entry) Chain(key EncodedString, rotateOptional bool) (*Entry, map[string]EncodedString, error) {
	var newEntry *Entry
	var outKeys map[string]EncodedString

	switch entry.Type {
	case "User":
		newEntry = NewUserEntry()
	case "Organization":
		newEntry = NewOrgEntry()
	default:
		return newEntry, outKeys, errors.New("unsupported entry type")
	}

	if key.Prefix != "ED25519" {
		return newEntry, outKeys, errors.New("unsupported signing key type")
	}

	if !entry.IsCompliant() {
		return newEntry, outKeys, errors.New("entry not compliant")
	}

	for k, v := range entry.Fields {
		newEntry.Fields[k] = v
	}

	index, err := strconv.ParseUint(newEntry.Fields["Index"], 10, 64)
	if err != nil {
		return newEntry, outKeys, errors.New("bad entry index value")
	}
	newEntry.Fields["Index"] = fmt.Sprintf("%d", index+1)

	switch entry.Type {
	case "User":
		outKeys, err = GenerateUserKeys(rotateOptional)
	case "Organization":
		outKeys, err = GenerateOrgKeys(rotateOptional)
	}
	if err != nil {
		return newEntry, outKeys, err
	}

	for _, info := range entry.Keys {
		keyString, ok := outKeys[info.Name+".public"]
		if ok {
			newEntry.Fields[info.Name] = keyString.AsString()
		} else if !info.Optional {
			panic("BUG: missing required keys generated for Chain() ")
		}
	}

	err = newEntry.Sign(key, "Custody")
	if err != nil {
		return newEntry, outKeys, err
	}

	return newEntry, outKeys, nil
}

// NewEntryFromData creates a new entry from a text block of entry information which includes the
// header and footer. The type of entry created is based on the information in the text block
func NewEntryFromData(textBlock string) (*Entry, error) {
	// CAUTION: This function needs to be extra careful because it handles untrusted data

	// The minimum number of lines is 11 because every org keycard, which is the smaller of the two,
	// has 9 required fields in addition to the Type line and the entry header and footer lines.
	lines := strings.Split(textBlock, "\r\n")
	if len(lines) < 11 {
		return nil, errors.New("entry too short")
	}

	var outEntry *Entry
	if lines[0] == "----- BEGIN USER ENTRY -----" {
		if lines[len(lines)-1] != "----- END USER ENTRY -----" {
			return nil, errors.New("bad entry header/footer")
		}

		// 9 required fields for User entries + header/footer lines + Type line
		if len(lines) < 12 {
			return nil, errors.New("entry too short")
		}

		if lines[1] != "Type:User" {
			return nil, errors.New("bad entry Type line")
		}

		outEntry = NewUserEntry()

	} else if lines[0] == "----- BEGIN ORG ENTRY -----" {
		if lines[len(lines)-1] != "----- END ORG ENTRY -----" {
			return nil, errors.New("bad entry header/footer")
		}

		if lines[1] != "Type:Organization" {
			return nil, errors.New("bad entry Type line")
		}

		outEntry = NewOrgEntry()
	} else {
		return nil, errors.New("bad entry data")
	}

	outEntry.Set([]byte(textBlock))
	return outEntry, nil
}

// NewOrgEntry creates a new OrgEntry
func NewOrgEntry() *Entry {
	self := new(Entry)
	self.Fields = make(map[string]string)
	self.Signatures = make(map[string]string)
	self.Keys = make([]KeyInfo, 4)

	self.Type = "Organization"
	self.FieldNames.Items = []string{
		"Index",
		"Name",
		"Contact-Admin",
		"Contact-Abuse",
		"Contact-Support",
		"Language",
		"Primary-Verification-Key",
		"Secondary-Verification-Key",
		"Encryption-Key",
		"Time-To-Live",
		"Expires",
		"Timestamp"}

	// If changes are made to the number of these fields, the minimum line count in NewEntryFromData
	// will need to be updated
	self.RequiredFields.Items = []string{
		"Index",
		"Name",
		"Contact-Admin",
		"Primary-Verification-Key",
		"Encryption-Key",
		"Time-To-Live",
		"Expires",
		"Timestamp"}

	self.Keys = []KeyInfo{
		{"Primary-Verification-Key", "signing", false},
		{"Secondary-Verification-Key", "signing", false},
		{"Encryption-Key", "encryption", true}}

	self.SignatureInfo.Items = []SigInfo{
		{"Custody", 1, true, SigInfoSignature},
		{"Organization", 2, false, SigInfoSignature},
		{"Hashes", 3, false, SigInfoHash}}

	self.Fields["Index"] = "1"
	self.Fields["Time-To-Live"] = "30"
	self.SetExpiration(-1)

	now := time.Now()
	self.Fields["Timestamp"] = fmt.Sprintf("%d%02d%02dT%02d%02d%02dZ", now.Year(), now.Month(),
		now.Day(), now.Hour(), now.Minute(), now.Second())

	return self
}

// validateOrgEntry checks the validity all OrgEntry data fields to ensure the data in them
// meets basic data validity checks
func (entry Entry) validateOrgEntry() (bool, error) {
	// Required field: Index
	pattern := regexp.MustCompile("[[:digit:]]+")
	if !pattern.MatchString(entry.Fields["Index"]) {
		return false, errors.New("bad index")
	}

	// Required field: Name
	// There are some stipulations to a person's name:
	// 1) the contents of the name field must contain at least 1 printable character
	// 2) maximum length of 64 code points
	pattern = regexp.MustCompile("^[[:space:]]+$")
	if !pattern.MatchString(entry.Fields["Name"]) {
		return false, errors.New("name field has no printable characters")
	}

	if utf8.RuneCountInString(entry.Fields["Name"]) > 64 {
		return false, errors.New("name field too long")
	}

	// Required field: Admin address
	pattern = regexp.MustCompile("^[\\da-fA-F]{8}-?[\\da-fA-F]{4}-?[\\da-fA-F]{4}-?[\\da-fA-F]{4}" +
		"-?[\\da-fA-F]{12}/([a-zA-Z0-9]+\x2E)+[a-zA-Z0-9]+$")
	if !pattern.MatchString(entry.Fields["Contact-Admin"]) {
		return false, errors.New("bad admin contact address")
	}

	// Required field: Primary Verification Key
	// We can't actually verify the key data, but we can ensure that it at least decodes from Base85
	_, err := b85.Decode(entry.Fields["Primary-Verification-Key"])
	if err != nil {
		return false, errors.New("bad primary verification key")
	}

	// Required field: Encryption Key
	_, err = b85.Decode(entry.Fields["Encryption-Key"])
	if err != nil {
		return false, errors.New("bad encryption key")
	}

	// Required field: Time To Live
	pattern = regexp.MustCompile("^[[:digit:]]{1,2}$")
	if !pattern.MatchString(entry.Fields["Time-To-Live"]) {
		return false, errors.New("bad time to live")
	}
	var intValue int
	intValue, err = strconv.Atoi(entry.Fields["Time-To-Live"])
	if intValue < 1 || intValue > 30 {
		return false, errors.New("time to live out of range")
	}

	// Required field: Expires
	pattern = regexp.MustCompile("^[[:digit:]]{8}$")
	if !pattern.MatchString(entry.Fields["Expires"]) {
		return false, errors.New("bad expiration date format")
	}

	year, _ := strconv.Atoi(entry.Fields["Expires"][0:3])
	month, _ := strconv.Atoi(entry.Fields["Expires"][4:5])
	day, _ := strconv.Atoi(entry.Fields["Expires"][6:7])

	var validDate bool
	validDate, err = isValidDate(month, day, year)
	if !validDate {
		return false, fmt.Errorf("bad expiration date %s", err.Error())
	}

	// Required field: Timestamp
	pattern = regexp.MustCompile("^[[:digit:]]{8}T[[:digit:]]{6}Z$")
	if !pattern.MatchString(entry.Fields["Timestamp"]) {
		return false, errors.New("bad timestamp format")
	}
	year, _ = strconv.Atoi(entry.Fields["Timestamp"][0:3])
	month, _ = strconv.Atoi(entry.Fields["Timestamp"][4:5])
	day, _ = strconv.Atoi(entry.Fields["Timestamp"][6:7])

	validDate, err = isValidDate(month, day, year)
	if !validDate {
		return false, fmt.Errorf("bad timestamp date %s", err.Error())
	}

	intValue, err = strconv.Atoi(entry.Fields["Timestamp"][9:10])
	if intValue > 23 {
		return false, fmt.Errorf("bad timestamp hours")
	}
	intValue, err = strconv.Atoi(entry.Fields["Timestamp"][11:12])
	if intValue > 59 {
		return false, fmt.Errorf("bad timestamp minutes")
	}
	intValue, err = strconv.Atoi(entry.Fields["Timestamp"][13:14])
	if intValue > 59 {
		return false, fmt.Errorf("bad timestamp seconds")
	}

	// Optional fields: Abuse address and Support addresses
	pattern = regexp.MustCompile("^[\\da-fA-F]{8}-?[\\da-fA-F]{4}-?[\\da-fA-F]{4}-?[\\da-fA-F]" +
		"{4}-?[\\da-fA-F]{12}/([a-zA-Z0-9]+\x2E)+[a-zA-Z0-9]+$")
	if strValue, ok := entry.Fields["Contact-Abuse"]; ok {
		if !pattern.MatchString(strValue) {
			return false, errors.New("bad abuse contact address")
		}
	}
	if strValue, ok := entry.Fields["Contact-Support"]; ok {
		if !pattern.MatchString(strValue) {
			return false, errors.New("bad support contact address")
		}
	}

	// Optional field: Language
	if strValue, ok := entry.Fields["Language"]; ok {
		pattern = regexp.MustCompile("^[[:alpha:]]{2,3}(,[[:alpha:]]{2,3})*?$")
		if !pattern.MatchString(strValue) {
			return false, errors.New("bad language list")
		}
	}

	// Optional field: Secondary Verification Key
	if strValue, ok := entry.Fields["Secondary-Verification-Key"]; ok {
		_, err = b85.Decode(strValue)
		if err != nil {
			return false, errors.New("bad secondary verification key")
		}
	}

	return true, nil
}

// NewUserEntry creates a new UserEntry
func NewUserEntry() *Entry {
	self := new(Entry)
	self.Fields = make(map[string]string)
	self.Signatures = make(map[string]string)
	self.Keys = make([]KeyInfo, 4)

	self.Type = "User"
	self.FieldNames.Items = []string{
		"Index",
		"Name",
		"Workspace-ID",
		"User-ID",
		"Domain",
		"Contact-Request-Verification-Key",
		"Contact-Request-Encryption-Key",
		"Public-Encryption-Key",
		"Alternate-Encryption-Key",
		"Time-To-Live",
		"Expires",
		"Timestamp"}

	self.Keys = []KeyInfo{
		{"Contact-Request-Verification-Key", "signing", false},
		{"Contact-Request-Encryption-Key", "encryption", false},
		{"Public-Encryption-Key", "encryption", true},
		{"Alternate-Encryption-Key", "encryption", true}}

	// If changes are made to the number of these fields, the minimum line count in NewEntryFromData
	// will need to be updated
	self.RequiredFields.Items = []string{
		"Index",
		"Workspace-ID",
		"Domain",
		"Contact-Request-Verification-Key",
		"Contact-Request-Encryption-Key",
		"Public-Encryption-Key",
		"Time-To-Live",
		"Expires",
		"Timestamp"}

	self.SignatureInfo.Items = []SigInfo{
		{"Custody", 1, true, SigInfoSignature},
		{"Organization", 2, false, SigInfoSignature},
		{"Hashes", 3, false, SigInfoHash},
		{"User", 4, false, SigInfoSignature}}

	self.Fields["Index"] = "1"
	self.Fields["Time-To-Live"] = "30"
	self.SetExpiration(-1)
	now := time.Now()
	self.Fields["Timestamp"] = fmt.Sprintf("%d%02d%02dT%02d%02d%02dZ", now.Year(), now.Month(),
		now.Day(), now.Hour(), now.Minute(), now.Second())

	return self
}

// validateUserEntry checks the validity all UserEntry data fields to ensure the data in them
// meets basic data validity checks. Note that this function only checks data format; it does
// not fail if the entry's Expires field is past due, the Timestamp field is in the future, etc.
func (entry Entry) validateUserEntry() (bool, error) {
	// Required field: Index
	pattern := regexp.MustCompile("[[:digit:]]+")
	if !pattern.MatchString(entry.Fields["Index"]) {
		return false, errors.New("bad index")
	}

	// Required field: Workspace-ID
	pattern = regexp.MustCompile("^[\\da-fA-F]{8}-?[\\da-fA-F]{4}-?[\\da-fA-F]{4}-?[\\da-fA-F]{4}" +
		"-?[\\da-fA-F]{12}$")
	if len(entry.Fields["Workspace-ID"]) != 36 && len(entry.Fields["Workspace-ID"]) != 32 {
		return false, errors.New("bad workspace id")
	}

	if !pattern.MatchString(entry.Fields["Workspace-ID"]) {
		return false, errors.New("bad workspace id")
	}

	// Required field: Domain
	pattern = regexp.MustCompile("([a-zA-Z0-9]+\x2E)+[a-zA-Z0-9]+")
	if !pattern.MatchString(entry.Fields["Domain"]) {
		return false, errors.New("bad domain")
	}

	// Required field: Contact Request Verification Key
	// We can't actually verify the key data, but we can ensure that it at least decodes from Base85
	_, err := b85.Decode(entry.Fields["Contact-Request-Verification-Key"])
	if err != nil {
		return false, errors.New("bad contact request verification key")
	}

	// Required field: Contact Request Encryption Key
	_, err = b85.Decode(entry.Fields["Contact-Request-Encryption-Key"])
	if err != nil {
		return false, errors.New("bad contact request encryption key")
	}

	// Required field: Public Encryption Key
	_, err = b85.Decode(entry.Fields["Public-Encryption-Key"])
	if err != nil {
		return false, errors.New("bad public encryption key")
	}

	// Required field: Time To Live
	pattern = regexp.MustCompile("^[[:digit:]]{1,2}$")
	if !pattern.MatchString(entry.Fields["Time-To-Live"]) {
		return false, errors.New("bad time to live")
	}
	var intValue int
	intValue, err = strconv.Atoi(entry.Fields["Time-To-Live"])
	if intValue < 1 || intValue > 30 {
		return false, errors.New("time to live out of range")
	}

	// Required field: Expires
	pattern = regexp.MustCompile("^[[:digit:]]{8}$")
	if !pattern.MatchString(entry.Fields["Expires"]) {
		return false, errors.New("bad expiration date format")
	}

	year, _ := strconv.Atoi(entry.Fields["Expires"][0:3])
	month, _ := strconv.Atoi(entry.Fields["Expires"][4:5])
	day, _ := strconv.Atoi(entry.Fields["Expires"][6:7])

	var validDate bool
	validDate, err = isValidDate(month, day, year)
	if !validDate {
		return false, fmt.Errorf("bad expiration date %s", err.Error())
	}

	// Required field: Timestamp
	pattern = regexp.MustCompile("^[[:digit:]]{8}T[[:digit:]]{6}Z$")
	if !pattern.MatchString(entry.Fields["Timestamp"]) {
		return false, errors.New("bad timestamp format")
	}
	year, _ = strconv.Atoi(entry.Fields["Timestamp"][0:3])
	month, _ = strconv.Atoi(entry.Fields["Timestamp"][4:5])
	day, _ = strconv.Atoi(entry.Fields["Timestamp"][6:7])

	validDate, err = isValidDate(month, day, year)
	if !validDate {
		return false, fmt.Errorf("bad timestamp date %s", err.Error())
	}

	intValue, err = strconv.Atoi(entry.Fields["Timestamp"][9:10])
	if intValue > 23 {
		return false, fmt.Errorf("bad timestamp hours")
	}
	intValue, err = strconv.Atoi(entry.Fields["Timestamp"][11:12])
	if intValue > 59 {
		return false, fmt.Errorf("bad timestamp minutes")
	}
	intValue, err = strconv.Atoi(entry.Fields["Timestamp"][13:14])
	if intValue > 59 {
		return false, fmt.Errorf("bad timestamp seconds")
	}

	// Optional field: Name
	if strValue, ok := entry.Fields["Name"]; ok {
		// There are some stipulations to a person's name:
		// 1) the contents of the name field must contain at least 1 printable character
		// 2) maximum length of 64 code points
		pattern = regexp.MustCompile("^[[:space:]]+$")
		if !pattern.MatchString(strValue) {
			return false, errors.New("name field has no printable characters")
		}

		if utf8.RuneCountInString(strValue) > 64 {
			return false, errors.New("name field too long")
		}
	}

	// Optional field: User ID
	if strValue, ok := entry.Fields["User-ID"]; ok {
		pattern = regexp.MustCompile("^[[:space:]]+$")
		if !pattern.MatchString(strValue) {
			return false, errors.New("user id contains whitespace")
		}

		pattern = regexp.MustCompile("[\\/\"]")
		if !pattern.MatchString(strValue) {
			return false, errors.New("user id contains illegal characters")
		}

		if utf8.RuneCountInString(strValue) > 64 {
			return false, errors.New("user id too long")
		}
	}

	// Optional field: Alternate Encryption Key
	if strValue, ok := entry.Fields["Alternate-Encryption-Key"]; ok {
		_, err = b85.Decode(strValue)
		if err != nil {
			return false, errors.New("bad alternate encryption key")
		}
	}

	return true, nil
}

// isValidDate handles basic date validation for this context. The year is expected to be at least
// 2020 and the month/day are expected to be valid
func isValidDate(m int, d int, y int) (bool, error) {
	if y < 2020 {
		return false, errors.New("year")
	}

	if m < 1 || m > 12 {
		return false, errors.New("month")
	}

	if d < 1 {
		return false, errors.New("day")
	}
	switch m {
	case 2:
		if y%4 == 0 && y%100 != 0 {
			if d > 29 {
				return false, errors.New("day")
			}
		} else if d > 28 {
			return false, errors.New("day")
		}
	case 1, 3, 5, 7, 8, 10, 12:
		if d > 31 {
			return false, errors.New("day")
		}
	default:
		if d > 30 {
			return false, errors.New("day")
		}
	}

	return true, nil
}

// GenerateOrgKeys generates a set of cryptographic keys for user entries, optionally including
// non-required keys
func GenerateOrgKeys(rotateOptional bool) (map[string]EncodedString, error) {
	var outKeys map[string]EncodedString
	if rotateOptional {
		outKeys = make(map[string]EncodedString, 10)
	} else {
		outKeys = make(map[string]EncodedString, 6)
	}

	var err error
	var ePublicKey, ePrivateKey *[32]byte
	var sPublicKey ed25519.PublicKey
	var sPrivateKey ed25519.PrivateKey

	ePublicKey, ePrivateKey, err = box.GenerateKey(rand.Reader)
	if err != nil {
		return outKeys, err
	}
	outKeys["Encryption-Key.public"] = EncodedString{"CURVE25519", b85.Encode(ePublicKey[:])}
	outKeys["Encryption-Key.private"] = EncodedString{"CURVE25519", b85.Encode(ePrivateKey[:])}

	sPublicKey, sPrivateKey, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return outKeys, err
	}
	outKeys["Primary-Verification-Key.public"] = EncodedString{"ED25519",
		b85.Encode(sPublicKey[:])}
	outKeys["Primary-Verification-Key.private"] = EncodedString{"ED25519",
		b85.Encode(sPrivateKey.Seed())}

	if rotateOptional {
		var asPublicKey ed25519.PublicKey
		var asPrivateKey ed25519.PrivateKey
		asPublicKey, asPrivateKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return outKeys, err
		}
		outKeys["Secondary-Verification-Key.public"] = EncodedString{"ED25519",
			b85.Encode(asPublicKey[:])}
		outKeys["Secondary-Verification-Key.private"] = EncodedString{"ED25519",
			b85.Encode(asPrivateKey.Seed())}
	}

	return outKeys, nil
}

// GenerateUserKeys generates a set of cryptographic keys for user entries, optionally including
// non-required keys
func GenerateUserKeys(rotateOptional bool) (map[string]EncodedString, error) {
	var outKeys map[string]EncodedString
	if rotateOptional {
		outKeys = make(map[string]EncodedString, 10)
	} else {
		outKeys = make(map[string]EncodedString, 6)
	}

	var err error
	var crePublicKey, crePrivateKey *[32]byte
	var sPublicKey, crsPublicKey ed25519.PublicKey
	var sPrivateKey, crsPrivateKey ed25519.PrivateKey

	sPublicKey, sPrivateKey, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return outKeys, err
	}
	outKeys["Primary-Verification-Key.public"] = EncodedString{"ED25519", b85.Encode(sPublicKey[:])}
	outKeys["Primary-Verification-Key.private"] = EncodedString{"ED25519", b85.Encode(sPrivateKey.Seed())}

	crePublicKey, crePrivateKey, err = box.GenerateKey(rand.Reader)
	if err != nil {
		return outKeys, err
	}
	outKeys["Contact-Request-Encryption-Key.public"] = EncodedString{"CURVE25519",
		b85.Encode(crePublicKey[:])}
	outKeys["Contact-Request-Encryption-Key.private"] = EncodedString{"CURVE25519",
		b85.Encode(crePrivateKey[:])}

	crsPublicKey, crsPrivateKey, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return outKeys, err
	}
	outKeys["Contact-Request-Verification-Key.public"] = EncodedString{"ED25519",
		b85.Encode(crsPublicKey[:])}
	outKeys["Contact-Request-Verification-Key.private"] = EncodedString{"ED25519",
		b85.Encode(crsPrivateKey.Seed())}

	if rotateOptional {
		var ePublicKey, ePrivateKey, altePublicKey, altePrivateKey *[32]byte

		ePublicKey, ePrivateKey, err = box.GenerateKey(rand.Reader)
		if err != nil {
			return outKeys, err
		}
		outKeys["Public-Encryption-Key.public"] = EncodedString{"CURVE25519",
			b85.Encode(ePublicKey[:])}
		outKeys["Public-Encryption-Key.private"] = EncodedString{"CURVE25519",
			b85.Encode(ePrivateKey[:])}

		altePublicKey, altePrivateKey, err = box.GenerateKey(rand.Reader)
		if err != nil {
			return outKeys, err
		}
		outKeys["Alternate-Encryption-Key.public"] = EncodedString{"CURVE25519",
			b85.Encode(altePublicKey[:])}
		outKeys["Alternate-Encryption-Key.private"] = EncodedString{"CURVE25519",
			b85.Encode(altePrivateKey[:])}
	} else {
		var emptyKey EncodedString
		outKeys["Public-Encryption-Key.public"] = emptyKey
		outKeys["Public-Encryption-Key.private"] = emptyKey
		outKeys["Alternate-Encryption-Key.public"] = emptyKey
		outKeys["Alternate-Encryption-Key.private"] = emptyKey
	}

	return outKeys, nil
}

// VerifyChain verifies the chain of custody between the provided previous entry and the current one.
func (entry Entry) VerifyChain(previous *Entry) (bool, error) {
	if previous.Type != entry.Type {
		return false, errors.New("entry type mismatch")
	}

	val, ok := entry.Signatures["Custody"]
	if !ok {
		return false, errors.New("custody signature missing")
	}
	if val == "" {
		return false, errors.New("custody signature empty")
	}

	verifyField := ""
	switch entry.Type {
	case "Organization":
		verifyField = "Primary-Verification-Key"
	case "User":
		verifyField = "Contact-Request-Verification-Key"
	default:
		return false, errors.New("unsupported entry type")
	}

	val, ok = entry.Fields[verifyField]
	if !ok {
		return false, errors.New("signing key missing in previous entry")
	}
	if val == "" {
		return false, errors.New("signing key entry in previous entry")
	}

	prevIndex, err := strconv.ParseUint(previous.Fields["Index"], 10, 64)
	if err != nil {
		return false, errors.New("previous entry has bad index value")
	}

	var index uint64
	index, err = strconv.ParseUint(entry.Fields["Index"], 10, 64)
	if err != nil {
		return false, errors.New("entry has bad index value")
	}

	if index != prevIndex+1 {
		return false, errors.New("entry index compliance failure")
	}

	var key EncodedString
	err = key.Set(previous.Fields[verifyField])
	if err != nil {
		return false, errors.New("bad signing key in previous entry")
	}

	var isValid bool
	isValid, err = entry.VerifySignature(key, "Custody")
	return isValid, err
}

// Keycard - class which houses a list of entries into a hash-linked chain
type Keycard struct {
	Type    string
	Entries []Entry
}

// Load writes the entire entry chain to one file with optional overwrite
func (card *Keycard) Load(path string, clobber bool) error {
	if len(path) < 1 {
		return errors.New("empty path")
	}

	fHandle, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fHandle.Close()

	fReader := bufio.NewReader(fHandle)

	var line string
	line, err = fReader.ReadString('\n')
	if err != nil {
		return err
	}

	accumulator := make([][2]string, 0, 16)
	cardType := ""
	lineIndex := 1
	for line != "" {
		line = strings.TrimSpace(line)
		if line == "" {
			lineIndex++
			continue
		}

		switch line {
		case "----- BEGIN ENTRY -----":
			accumulator = make([][2]string, 0, 16)

		case "----- END ENTRY -----":
			var currentEntry *Entry
			switch cardType {
			case "User":
				currentEntry = NewUserEntry()
			case "Organization":
				currentEntry = NewOrgEntry()
			default:
				return errors.New("unsupported entry type ")
			}

			for _, fieldData := range accumulator {
				err = currentEntry.SetField(fieldData[0], fieldData[1])
				if err != nil {
					return fmt.Errorf("bad field data in card line %d", lineIndex)
				}
			}

		default:
			parts := strings.SplitN(line, ":", 1)
			if len(parts) != 2 {
				return fmt.Errorf("bad line data in card line %d", lineIndex)
			}

			if parts[0] == "Type" {
				if cardType != "" {
					if cardType != parts[1] {
						return fmt.Errorf("keycard-entry type mismatch in line %d", lineIndex)
					}
				} else {
					cardType = parts[0]
				}
			}
			accumulator = append(accumulator, [2]string{parts[0], parts[1]})
		}

		line, err = fReader.ReadString('\n')
		if err != nil {
			return err
		}
		lineIndex++
	}

	return nil
}

// Save writes the entire entry chain to one file with optional overwrite
func (card Keycard) Save(path string, clobber bool) error {
	if len(path) < 1 {
		return errors.New("empty path")
	}

	_, err := os.Stat(path)
	if !os.IsNotExist(err) && !clobber {
		return errors.New("file exists")
	}

	fHandle, err := os.Create(path)
	if err != nil {
		return err
	}
	fHandle.Close()

	for _, entry := range card.Entries {
		_, err = fHandle.Write([]byte("----- BEGIN ENTRY -----\r\n"))
		if err != nil {
			return err
		}

		_, err = fHandle.Write(entry.MakeByteString(-1))
		if err != nil {
			return err
		}

		_, err = fHandle.Write([]byte("----- END ENTRY -----\r\n"))
		if err != nil {
			return err
		}
	}

	return nil
}

// VerifyChain verifies the entire chain of entries
func (card Keycard) VerifyChain(path string, clobber bool) (bool, error) {
	if len(card.Entries) < 1 {
		return false, errors.New("no entries in keycard")
	}

	if len(card.Entries) == 1 {
		return true, nil
	}

	for i := 0; i < len(card.Entries)-1; i++ {
		verifyStatus, err := card.Entries[i].VerifyChain(&card.Entries[i+1])
		if err != nil || !verifyStatus {
			return false, err
		}
	}
	return true, nil
}
