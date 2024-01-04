package messaging

import (
	"regexp"
	"strings"
	"sync"

	"github.com/spf13/viper"
	ezn "gitlab.com/darkwyrm/goeznacl"
	"gitlab.com/mensago/mensagod/dbhandler"
	"gitlab.com/mensago/mensagod/misc"
)

type SealedEnvelope struct {
	Type       string
	Version    string
	Receiver   string
	Sender     string
	Date       string
	PayloadKey string
}

type Envelope struct {
	Type       string
	Version    string
	Receiver   RecipientInfo
	Sender     SenderInfo
	Date       string
	PayloadKey string
}

type SealedMessage struct {
	Envelope SealedEnvelope
	Payload  string
}

type RecipientInfo struct {
	// To contains the full recipient address
	To string

	// Sender contains only the domain of origin
	SenderDomain string
}

type SenderInfo struct {
	// From contains the full sender address
	From string

	// Receiver contains only the destination's domain
	RecipientDomain string
}

type MsgBody struct {
	From        string
	To          string
	Date        string
	ThreadID    string
	Subject     string
	Body        string
	Attachments []Attachment
}

type Attachment struct {
	Name string
	Type string
	Data string
}

// widList is a map of workspace IDs to UNIX timestamps used for update notifications. The
// timestamp for a workspace is periodically checked by all worker goroutines which handle it. The
// timestamp is updated by either a delivery goroutine or a worker goroutine when a new message
// is placed in <wid>/new. Worker goroutines can then notify client devices of new messages.
var widList map[string]int64
var widListLock sync.RWMutex

func init() {
	widList = make(map[string]int64)
}

// RegisterWorkspace ensures that the workspace update list has a specific workspace ID. If it has
// already been registered, nothing happens.
func RegisterWorkspace(wid string) error {
	if !dbhandler.ValidateUUID(wid) {
		return misc.ErrInvalidID
	}

	widListLock.Lock()
	defer widListLock.Unlock()

	_, exists := widList[wid]
	if !exists {
		widList[wid] = -1
	}

	return nil
}

// IsWorkspaceRegisters checks to see if a client has been monitoring the workspace
func IsWorkspaceRegistered(wid string) bool {
	if !dbhandler.ValidateUUID(wid) {
		return false
	}

	widListLock.RLock()
	defer widListLock.RUnlock()

	_, exists := widList[wid]
	return exists
}

// Gets the UTC UNIX timestamp of the last new message notification for the workspace. If none
// has occurred, then -1 in returned.
func LastWorkspaceUpdate(wid string) int64 {
	widListLock.RLock()
	defer widListLock.RUnlock()

	timestamp, exists := widList[wid]
	if !exists {
		return -1
	}

	return timestamp
}

// UpdateWorkspace updates the timestamp for the last new message for a workspace
func UpdateWorkspace(wid string, timestamp int64) error {
	if !dbhandler.ValidateUUID(wid) {
		return misc.ErrInvalidID
	}

	widListLock.Lock()
	defer widListLock.Unlock()

	widList[wid] = timestamp

	return nil
}

// GetOrgEncryptionKey obtains an organization's encryption key and returns it as a CryptoString
func GetOrgEncryptionKey(domain string) (ezn.CryptoString, error) {

	pattern := regexp.MustCompile("([a-zA-Z0-9]+\x2E)+[a-zA-Z0-9]+")
	if !pattern.MatchString(domain) {
		return ezn.CryptoString{}, misc.ErrInvalidDomain
	}

	if strings.EqualFold(domain, viper.GetString("global.domain")) {
		encpair, err := dbhandler.GetEncryptionPair()
		if err != nil {
			return ezn.CryptoString{}, err
		}
		return encpair.PublicKey, nil
	}

	// TODO: POSTDEMO: Implement getting keys for external servers

	return ezn.CryptoString{}, misc.ErrUnimplemented
}

// GetOrgEncryptionKey obtains an organization's verification key and returns it as a CryptoString
func GetOrgVerificationKey(domain string) (ezn.CryptoString, error) {

	pattern := regexp.MustCompile("([a-zA-Z0-9]+\x2E)+[a-zA-Z0-9]+")
	if !pattern.MatchString(domain) {
		return ezn.CryptoString{}, misc.ErrInvalidDomain
	}

	if strings.EqualFold(domain, viper.GetString("global.domain")) {
		signpair, err := dbhandler.GetPrimarySigningPair()
		if err != nil {
			return ezn.CryptoString{}, err
		}
		return signpair.PublicKey, nil
	}

	// TODO: POSTDEMO: Implement getting keys for external servers

	return ezn.CryptoString{}, misc.ErrUnimplemented
}
