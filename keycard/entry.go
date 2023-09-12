package keycard

import (
	"crypto/ed25519"
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

	"github.com/zeebo/blake3"
	"gitlab.com/darkwyrm/b85"
	ezn "gitlab.com/darkwyrm/goeznacl"
	"gitlab.com/darkwyrm/gostringlist"
	"gitlab.com/mensago/mensagod/logging"
	"gitlab.com/mensago/mensagod/misc"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

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
func (entry *Entry) IsDataCompliant() bool {
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
func (entry Entry) IsExpired() (bool, error) {

	_, err := StringToExpiration(entry.Fields["Expires"])
	if err != nil {
		return false, err
	}

	now := time.Now()
	expiration, _ := time.Parse("2006-01-02", entry.Fields["Expires"])
	return now.After(expiration), nil
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
			logging.Write("invalid signature info type in Entry.MakeByteString")
			return nil
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
		return misc.ErrMissingArgument
	}

	_, err := os.Stat(path)
	if !os.IsNotExist(err) && !clobber {
		return os.ErrExist
	}

	return ioutil.WriteFile(path, entry.MakeByteString(-1), 0644)
}

// SetField sets an entry field to the specified value.
func (entry *Entry) SetField(fieldName string, fieldValue string) error {
	if len(fieldName) < 1 {
		return misc.ErrMissingArgument
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
		return misc.ErrMissingArgument
	}

	lines := strings.Split(string(data), "\r\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	stripHeader := false
	if entry.Type == "Organization" {
		if lines[0] == "----- BEGIN ENTRY -----" {
			if lines[len(lines)-1] != "----- END ENTRY -----" {
				return errors.New("bad entry header/footer")
			}
			stripHeader = true
		} else if lines[0] != "Type:Organization" {
			return misc.ErrMismatch
		}

	} else if entry.Type == "User" {
		if lines[0] == "----- BEGIN ENTRY -----" {
			if lines[len(lines)-1] != "----- END ENTRY -----" {
				return errors.New("bad entry header/footer")
			}
			stripHeader = true
		} else if lines[0] != "Type:User" {
			return misc.ErrMismatch
		}
	} else {
		return errors.New("bad entry type")
	}

	startLine := 0
	endLine := len(lines)
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
				return fmt.Errorf("can't use %s data on %s entries", parts[1], entry.Type)
			}
		} else if strings.HasSuffix(parts[0], "Signature") {
			sigNameParts := strings.SplitN(parts[0], "-", 2)
			if !entry.SignatureInfo.Contains(sigNameParts[0]) {
				return fmt.Errorf("%s is not a valid signature type", sigNameParts[0])
			}

			entry.Signatures[sigNameParts[0]] = parts[1]

		} else if parts[0] == "Hash" {
			entry.Hash = parts[1]

		} else if parts[0] == "Previous-Hash" {
			entry.PrevHash = parts[1]

		} else {
			entry.Fields[parts[0]] = parts[1]
		}
	}

	return nil
}

func (entry *Entry) Duplicate() *Entry {
	var out Entry
	out.Type = entry.Type

	out.Fields = make(map[string]string, len(entry.Fields))
	for item, value := range entry.Fields {
		out.Fields[item] = value
	}
	out.FieldNames = entry.FieldNames.Copy()
	out.RequiredFields = entry.RequiredFields.Copy()

	out.Signatures = make(map[string]string, len(entry.Signatures))
	copy(out.SignatureInfo.Items, entry.SignatureInfo.Items)
	out.PrevHash = entry.PrevHash
	out.Hash = entry.Hash
	copy(out.Keys, entry.Keys)

	return &out
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

	entry.Fields["Expires"] = time.Now().AddDate(0, 0, int(numdays)).Format("20060102")

	return nil
}

// Sign cryptographically signs an entry. The supported types and expected order of the signature
// is defined by subclasses using the SigInfo instances in the object's SignatureInfo property.
// Adding a particular signature causes those that must follow it to be cleared. The Entry's
// cryptographic hash counts as a signature in this matter. Thus, if an Organization signature is
// added to the entry, the instance's hash and User signatures are both cleared.
func (entry *Entry) Sign(signingKey ezn.CryptoString, sigtype string) error {
	if !signingKey.IsValid() {
		return errors.New("bad signing key")
	}

	if signingKey.Prefix != "ED25519" {
		return ezn.ErrUnsupportedAlgorithm
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

	signkeyDecoded := signingKey.RawData()
	if signkeyDecoded == nil {
		return errors.New("base signing key")
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
		return ezn.ErrUnsupportedAlgorithm
	}

	hashLevel := -1
	for i := range entry.SignatureInfo.Items {
		if entry.SignatureInfo.Items[i].Type == SigInfoHash {
			hashLevel = entry.SignatureInfo.Items[i].Level
			break
		}
	}

	if hashLevel < 0 {
		logging.Write("SignatureInfo missing hash entry")
		return errors.New("bug: SignatureInfo missing hash entry")
	}

	switch algorithm {
	case "BLAKE3-256":
		// The API for Zeebo's BLAKE3 implementation isn't the same as the other hash APIs. It
		// requires a bit more effort. :(
		var sum []byte
		hasher := blake3.New()
		hasher.Write(entry.MakeByteString(hashLevel))
		hasher.Sum(sum)
		entry.Hash = algorithm + ":" + b85.Encode(sum)
	case "BLAKE2B-256":
		sum := blake2b.Sum256(entry.MakeByteString(hashLevel))
		entry.Hash = algorithm + ":" + b85.Encode(sum[:])
	case "SHA-256":
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
func (entry Entry) VerifySignature(verifyKey ezn.CryptoString, sigtype string) (bool, error) {

	if !verifyKey.IsValid() {
		return false, errors.New("bad verification key")
	}

	if verifyKey.Prefix != "ED25519" {
		return false, ezn.ErrUnsupportedAlgorithm
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

	var sig ezn.CryptoString
	err := sig.Set(entry.Signatures[sigtype])
	if err != nil {
		return false, err
	}
	if sig.Prefix != "ED25519" {
		return false, ezn.ErrUnsupportedAlgorithm
	}
	digest := sig.RawData()
	if digest == nil {
		return false, errors.New("decoding error in signature")
	}

	verifyKeyDecoded := verifyKey.RawData()
	if verifyKeyDecoded == nil {
		return false, errors.New("decoding error in verification key")
	}

	verifyStatus := ed25519.Verify(verifyKeyDecoded, entry.MakeByteString(sigInfo.Level-1), digest)

	return verifyStatus, nil
}

// Chain creates a new Entry object with new keys and a custody signature. It requires the
// previous contact request signing key passed as an ezn.ezn. The new keys are returned with the
// string '.private' or '.public' appended to the key's field name, e.g.
// Primary-Encryption-Key.public.
//
// Note that a user's public encryption keys and an organization's alternate verification key are
// not required to be updated during entry rotation so that they can be rotated on a different
// schedule from the other keys.
func (entry *Entry) Chain(key ezn.CryptoString, rotateOptional bool) (*Entry, map[string]ezn.CryptoString, error) {
	var newEntry *Entry
	var outKeys map[string]ezn.CryptoString

	switch entry.Type {
	case "User":
		newEntry = NewUserEntry()
	case "Organization":
		newEntry = NewOrgEntry()
	default:
		return newEntry, outKeys, errors.New("unsupported entry type")
	}

	if key.Prefix != "ED25519" {
		return newEntry, outKeys, ezn.ErrUnsupportedAlgorithm
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
		outKeys, err = GenerateUserKeys()
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
			logging.Write("missing required keys generated for Chain()")
			return nil, nil, errors.New("missing required keys generated for Chain()")
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

	// The minimum number of lines is 12 because every org keycard, which is the smaller of the two,
	// has 9 required fields in addition to the Type line and the entry header and footer lines.
	lines := strings.Split(textBlock, "\r\n")
	if len(lines) < 12 {
		return nil, errors.New("entry too short")
	}

	var outEntry *Entry
	if lines[0] == "Type:User" {
		// 10 required fields for User entries + Type line
		if len(lines) < 11 {
			return nil, errors.New("entry too short")
		}

		outEntry = NewUserEntry()

	} else if lines[0] == "Type:Organization" {
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
		"Domain",
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
		"Domain",
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
		{"Hashes", 2, false, SigInfoHash},
		{"Organization", 3, false, SigInfoSignature}}

	self.Fields["Index"] = "1"
	self.Fields["Time-To-Live"] = "30"
	self.SetExpiration(-1)

	self.Fields["Timestamp"] = time.Now().UTC().Format("20060102T030405Z")

	return self
}

// validateOrgEntry checks the validity all OrgEntry data fields to ensure the data in them
// meets basic data validity checks
func (entry *Entry) validateOrgEntry() (bool, error) {
	// Required field: Index
	pattern := regexp.MustCompile("[[:digit:]]+")
	if !pattern.MatchString(entry.Fields["Index"]) {
		return false, errors.New("bad index")
	}
	var intValue int
	intValue, _ = strconv.Atoi(entry.Fields["Index"])
	if intValue < 1 {
		return false, errors.New("bad index value")
	}

	// Required field: Name
	// There are some stipulations to a person's name:
	// 1) the contents of the name field must contain at least 1 printable character
	// 2) maximum length of 64 code points
	pattern = regexp.MustCompile("^[[:space:]]+$")
	if pattern.MatchString(entry.Fields["Name"]) {
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
	var keystr ezn.CryptoString
	err := keystr.Set(entry.Fields["Primary-Verification-Key"])
	if err != nil {
		return false, errors.New("bad primary verification key")
	}
	if keystr.RawData() == nil {
		return false, errors.New("bad primary verification key")
	}

	// Required field: Encryption Key
	err = keystr.Set(entry.Fields["Encryption-Key"])
	if err != nil {
		return false, errors.New("bad encryption key")
	}
	if keystr.RawData() == nil {
		return false, errors.New("bad encryption key")
	}

	// Required field: Time To Live
	pattern = regexp.MustCompile("^[[:digit:]]{1,2}$")
	if !pattern.MatchString(entry.Fields["Time-To-Live"]) {
		return false, errors.New("bad time to live")
	}

	intValue, _ = strconv.Atoi(entry.Fields["Time-To-Live"])
	if intValue < 1 || intValue > 30 {
		return false, errors.New("time to live out of range")
	}

	// Required field: Expires
	_, err = StringToExpiration(entry.Fields["Expires"])
	if err != nil {
		return false, err
	}

	// Required field: Timestamp
	_, err = StringToTimestamp(entry.Fields["Timestamp"])
	if err != nil {
		return false, err
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
		err = keystr.Set(strValue)
		if err != nil {
			return false, errors.New("bad secondary verification key")
		}
		if keystr.RawData() == nil {
			return false, errors.New("bad secondary verification key")
		}
	}

	if IsTimestampValid(entry.Fields["Timestamp"]) != nil {
		return false, errors.New("invalid timestamp")
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
		"User-ID",
		"Workspace-ID",
		"Domain",
		"Contact-Request-Verification-Key",
		"Contact-Request-Encryption-Key",
		"Encryption-Key",
		"Verification-Key",
		"Time-To-Live",
		"Expires",
		"Timestamp"}

	self.Keys = []KeyInfo{
		{"Contact-Request-Verification-Key", "signing", false},
		{"Contact-Request-Encryption-Key", "encryption", false},
		{"Encryption-Key", "encryption", false},
		{"Verification-Key", "signing", false}}

	// If changes are made to the number of these fields, the minimum line count in NewEntryFromData
	// will need to be updated
	self.RequiredFields.Items = []string{
		"Index",
		"Workspace-ID",
		"Domain",
		"Contact-Request-Verification-Key",
		"Contact-Request-Encryption-Key",
		"Encryption-Key",
		"Verification-Key",
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
	self.Fields["Timestamp"] = time.Now().UTC().Format("20060102T030405Z")

	return self
}

// validateUserEntry checks the validity all UserEntry data fields to ensure the data in them
// meets basic data validity checks. Note that this function only checks data format; it does
// not fail if the entry's Expires field is past due, the Timestamp field is in the future, etc.
func (entry *Entry) validateUserEntry() (bool, error) {
	// Required field: Index
	pattern := regexp.MustCompile("[[:digit:]]+")
	if !pattern.MatchString(entry.Fields["Index"]) {
		return false, errors.New("bad index")
	}
	var intValue int
	intValue, _ = strconv.Atoi(entry.Fields["Index"])
	if intValue < 1 {
		return false, errors.New("bad index value")
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

	// Required fields: Contact Request Verification Key, Contact Request Encryption Key,
	// 					Public Encryption Key, Public Verification Key
	// We can't actually verify the key data, but we can ensure that it at least decodes from Base85
	keyFields := []string{
		"Contact-Request-Verification-Key",
		"Contact-Request-Encryption-Key",
		"Encryption-Key",
		"Verification-Key",
	}

	for _, fieldName := range keyFields {
		var keystr ezn.CryptoString
		err := keystr.Set(entry.Fields[fieldName])
		if err != nil || keystr.RawData() == nil {
			return false, fmt.Errorf("bad key field: %s", fieldName)
		}
	}

	// Required field: Time To Live
	pattern = regexp.MustCompile("^[[:digit:]]{1,2}$")
	if !pattern.MatchString(entry.Fields["Time-To-Live"]) {
		return false, errors.New("bad time to live")
	}
	intValue, _ = strconv.Atoi(entry.Fields["Time-To-Live"])
	if intValue < 1 || intValue > 30 {
		return false, errors.New("time to live out of range")
	}

	// Required field: Expires
	_, err := StringToExpiration(entry.Fields["Expires"])
	if err != nil {
		return false, err
	}

	// Required field: Timestamp
	if IsTimestampValid(entry.Fields["Timestamp"]) != nil {
		return false, errors.New("invalid timestamp")
	}

	// Optional field: Name
	if strValue, ok := entry.Fields["Name"]; ok {
		// There are some stipulations to a person's name:
		// 1) the contents of the name field must contain at least 1 printable character
		// 2) maximum length of 64 code points
		pattern = regexp.MustCompile("^[[:space:]]+$")
		if pattern.MatchString(strValue) {
			return false, errors.New("name field has no printable characters")
		}

		if utf8.RuneCountInString(strValue) > 64 {
			return false, errors.New("name field too long")
		}
	}

	// Optional field: User ID
	if strValue, ok := entry.Fields["User-ID"]; ok {
		pattern = regexp.MustCompile("[[:space:]]+")
		if pattern.MatchString(strValue) {
			return false, errors.New("user id contains whitespace")
		}

		// pattern = regexp.MustCompile("[\\/\"]")
		pattern = regexp.MustCompile("[\\\\/\"]")
		if pattern.MatchString(strValue) {
			return false, errors.New("user id contains illegal characters")
		}

		if utf8.RuneCountInString(strValue) > 64 {
			return false, errors.New("user id too long")
		}
	}

	return true, nil
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

	var key ezn.CryptoString
	err = key.Set(previous.Fields[verifyField])
	if err != nil {
		return false, errors.New("bad signing key in previous entry")
	}

	var isValid bool
	isValid, err = entry.VerifySignature(key, "Custody")
	return isValid, err
}
