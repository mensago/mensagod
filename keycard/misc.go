package keycard

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	ezn "gitlab.com/darkwyrm/goeznacl"
	"golang.org/x/crypto/nacl/box"
)

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

type Timestamp struct {
	Year   int
	Month  int
	Day    int
	Hour   int
	Minute int
	Second int
}

func StringToTimestamp(timestr string) (Timestamp, error) {
	var out Timestamp

	pattern := regexp.MustCompile("^[[:digit:]]{4}-[[:digit:]]{2}-[[:digit:]]{2}T[[:digit:]]{2}:[[:digit:]]{2}:[[:digit:]]{2}Z$")
	if !pattern.MatchString(timestr) {
		return out, errors.New("bad timestamp format")
	}
	out.Year, _ = strconv.Atoi(timestr[0:4])
	out.Month, _ = strconv.Atoi(timestr[5:7])
	out.Day, _ = strconv.Atoi(timestr[8:10])

	validDate, err := isValidDate(out.Month, out.Day, out.Year)
	if !validDate {
		return out, fmt.Errorf("bad timestamp date %s", err.Error())
	}

	out.Hour, _ = strconv.Atoi(timestr[11:13])
	if out.Hour > 23 {
		return out, fmt.Errorf("bad timestamp hours")
	}
	out.Minute, _ = strconv.Atoi(timestr[14:16])
	if out.Minute > 59 {
		return out, fmt.Errorf("bad timestamp minutes")
	}
	out.Second, _ = strconv.Atoi(timestr[17:19])
	if out.Second > 59 {
		return out, fmt.Errorf("bad timestamp seconds")
	}

	return out, nil
}

func StringToExpiration(timestr string) (Timestamp, error) {
	var out Timestamp

	pattern := regexp.MustCompile("^[[:digit:]]{4}-[[:digit:]]{2}-[[:digit:]]{2}$")
	if !pattern.MatchString(timestr) {
		return out, errors.New("bad expiration format")
	}
	out.Year, _ = strconv.Atoi(timestr[0:4])
	out.Month, _ = strconv.Atoi(timestr[5:7])
	out.Day, _ = strconv.Atoi(timestr[8:10])

	validDate, err := isValidDate(out.Month, out.Day, out.Year)
	if !validDate {
		return out, fmt.Errorf("bad timestamp date %s", err.Error())
	}

	return out, nil
}

// IsTimestampValid returns true if the timestamp for the entry is valid
func IsTimestampValid(timestr string) error {

	_, err := StringToTimestamp(timestr)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	timestamp, err := time.Parse("2006-01-02T15:04:05Z", timestr)
	if err != nil {
		return err
	}
	if now.Before(timestamp) {
		return errors.New("timestamp is in the future")
	}

	return nil
}

// IsExpirationValid returns true if the expiration for the entry is valid
func IsExpirationValid(timestr string) error {

	_, err := StringToExpiration(timestr)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	timestamp, err := time.Parse("2006-01-02T15:04:05Z", timestr)
	if err != nil {
		return err
	}
	if now.After(timestamp) {
		return errors.New("expiration has past")
	}

	return nil
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
func GenerateOrgKeys(rotateOptional bool) (map[string]ezn.CryptoString, error) {
	var outKeys map[string]ezn.CryptoString
	if rotateOptional {
		outKeys = make(map[string]ezn.CryptoString, 10)
	} else {
		outKeys = make(map[string]ezn.CryptoString, 6)
	}

	var err error
	var ePublicKey, ePrivateKey *[32]byte
	var sPublicKey ed25519.PublicKey
	var sPrivateKey ed25519.PrivateKey

	ePublicKey, ePrivateKey, err = box.GenerateKey(rand.Reader)
	if err != nil {
		return outKeys, err
	}
	outKeys["Encryption-Key.public"] = ezn.NewCSFromBytes("CURVE25519", ePublicKey[:])
	outKeys["Encryption-Key.private"] = ezn.NewCSFromBytes("CURVE25519", ePrivateKey[:])

	sPublicKey, sPrivateKey, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return outKeys, err
	}
	outKeys["Primary-Verification-Key.public"] = ezn.NewCSFromBytes("ED25519", sPublicKey[:])
	outKeys["Primary-Verification-Key.private"] = ezn.NewCSFromBytes("ED25519", sPrivateKey.Seed())

	if rotateOptional {
		var asPublicKey ed25519.PublicKey
		var asPrivateKey ed25519.PrivateKey
		asPublicKey, asPrivateKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return outKeys, err
		}
		outKeys["Secondary-Verification-Key.public"] = ezn.NewCSFromBytes("ED25519", asPublicKey[:])
		outKeys["Secondary-Verification-Key.private"] = ezn.NewCSFromBytes("ED25519",
			asPrivateKey.Seed())
	}

	return outKeys, nil
}

// GenerateUserKeys generates a set of cryptographic keys for user entries, optionally including
// non-required keys
func GenerateUserKeys() (map[string]ezn.CryptoString, error) {
	outKeys := make(map[string]ezn.CryptoString, 10)

	var err error
	var crePublicKey, crePrivateKey *[32]byte
	var sPublicKey, crsPublicKey ed25519.PublicKey
	var sPrivateKey, crsPrivateKey ed25519.PrivateKey

	sPublicKey, sPrivateKey, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return outKeys, err
	}
	outKeys["Verification-Key.public"] = ezn.NewCSFromBytes("ED25519", sPublicKey[:])
	outKeys["Verification-Key.private"] = ezn.NewCSFromBytes("ED25519", sPrivateKey.Seed())

	crePublicKey, crePrivateKey, err = box.GenerateKey(rand.Reader)
	if err != nil {
		return outKeys, err
	}
	outKeys["Contact-Request-Encryption-Key.public"] = ezn.NewCSFromBytes("CURVE25519",
		crePublicKey[:])
	outKeys["Contact-Request-Encryption-Key.private"] = ezn.NewCSFromBytes("CURVE25519",
		crePrivateKey[:])

	crsPublicKey, crsPrivateKey, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return outKeys, err
	}
	outKeys["Contact-Request-Verification-Key.public"] = ezn.NewCSFromBytes("ED25519",
		crsPublicKey[:])
	outKeys["Contact-Request-Verification-Key.private"] = ezn.NewCSFromBytes("ED25519",
		crsPrivateKey.Seed())

	var ePublicKey, ePrivateKey *[32]byte

	ePublicKey, ePrivateKey, err = box.GenerateKey(rand.Reader)
	if err != nil {
		return outKeys, err
	}
	outKeys["Encryption-Key.public"] = ezn.NewCSFromBytes("CURVE25519", ePublicKey[:])
	outKeys["Encryption-Key.private"] = ezn.NewCSFromBytes("CURVE25519", ePrivateKey[:])

	return outKeys, nil
}
