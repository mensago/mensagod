package messaging

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	cs "github.com/darkwyrm/mensagod/cryptostring"
	"github.com/darkwyrm/mensagod/dbhandler"
	"github.com/darkwyrm/mensagod/ezcrypt"
	"github.com/spf13/viper"
)

type SealedEnvelope struct {
	Type       string
	Version    string
	Receiver   string
	Sender     string
	Date       string
	PayloadKey string
	Payload    string
}

type Envelope struct {
	Type       string
	Version    string
	Receiver   RecipientInfo
	Sender     SenderInfo
	Date       string
	PayloadKey string
	Payload    MsgBody
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

// Allocate a new message
func NewMessage() *Envelope {
	var out Envelope
	out.Version = "1.0"
	out.Payload.Attachments = make([]Attachment, 0)
	return &out
}

// Seal turns a regular unencrypted message into encrypted one ready for transport. Note that the
// process used for this function is specific to sealing system messages sent by the server.
func (e *Envelope) Seal(recipientKey cs.CryptoString) (*SealedEnvelope, error) {
	// Implementation:
	// Set sender information, marshal to JSON, get org key, encrypt, and assign
	// Set recipient information, marshal to JSON, encrypt with supplied key, and assign
	// Generate ephemeral message key, encrypt, and assign
	// Marshal payload to JSON, encrypt with ephemeral message key, and assign

	var out SealedEnvelope

	// Set sender information, marshal to JSON, get org key, encrypt, and assign
	e.Sender.From = viper.GetString("global.domain")
	e.Receiver.SenderDomain = e.Sender.From

	rawJSON, err := json.Marshal(e.Sender)
	if err != nil {
		return nil, err
	}

	sOrgKeyCS, err := GetOrgEncryptionKey(e.Sender.From)
	if err != nil {
		return nil, err
	}
	sPubKey := ezcrypt.NewEncryptionKey(*sOrgKeyCS)
	out.Sender, err = sPubKey.Encrypt([]byte(rawJSON))
	if err != nil {
		return nil, err
	}

	// TODO: Finish implementing

	return &out, errors.New("Unimplemented")
}

func (se *SealedEnvelope) Send(address string) error {
	now := time.Now().UTC()
	se.Date = fmt.Sprintf("%d%02d%02dT%02d%02d%02dZ", now.Year(), now.Month(), now.Day(), now.Hour(),
		now.Minute(), now.Second())

	// TODO: Finish implementing

	return errors.New("Unimplemented")
}

func (se *SealedEnvelope) SendLocal(wid string) error {
	now := time.Now().UTC()
	se.Date = fmt.Sprintf("%d%02d%02dT%02d%02d%02dZ", now.Year(), now.Month(), now.Day(), now.Hour(),
		now.Minute(), now.Second())

	// TODO: Finish implementing

	return errors.New("Unimplemented")
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
		return errors.New("invalid workspace id")
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
		return errors.New("invalid workspace id")
	}

	widListLock.Lock()
	defer widListLock.Unlock()

	widList[wid] = timestamp

	return nil
}

// GetOrgEncryptionKey obtains an organization's encryption key and returns it as a CryptoString
func GetOrgEncryptionKey(domain string) (*cs.CryptoString, error) {

	// TODO: Implement
	return nil, errors.New("unimplemented")
}

// GetOrgEncryptionKey obtains an organization's verification key and returns it as a CryptoString
func GetOrgVerificationKey(domain string) (*cs.CryptoString, error) {

	// TODO: Implement
	return nil, errors.New("unimplemented")
}
