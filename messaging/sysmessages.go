package messaging

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	ezn "gitlab.com/darkwyrm/goeznacl"
	"gitlab.com/mensago/mensagod/config"
	"gitlab.com/mensago/mensagod/dbhandler"
	"gitlab.com/mensago/mensagod/kcresolver"
	"gitlab.com/mensago/mensagod/logging"
	"gitlab.com/mensago/mensagod/types"
)

func NewDeviceApproval(wid types.RandomID, devid types.RandomID,
	addr net.Addr) (SealedSysMessage, error) {

	userAddr, err := dbhandler.ResolveWID(wid)
	if err != nil {
		return SealedSysMessage{}, err
	}

	body := fmt.Sprintf("Timestamp:%s\r\nIP-Address:%s\r\n",
		time.Now().UTC().Format("2006-01-02 03:04:05"), addr.String())

	return NewSysMessage("devrequest", userAddr, "New Device Login", body)
}

// NewSysMessage() is used to create system messages intended for delivery to a local user. Note
// that system messages can be sent to both local and remote recipients
func NewSysMessage(msgType string, recipient types.WAddress, subject string,
	body string) (SealedSysMessage, error) {

	var out SealedSysMessage

	now := time.Now().UTC()
	sendingServerPair, err := dbhandler.GetEncryptionPair()
	if err != nil {
		logging.Writef("NewSysMessage: unable to get org encryption pair: %s", err.Error())
		return out, err
	}

	var maddr = recipient.AsMAddress()
	recipientOrgCard, err := kcresolver.GetKeycard(maddr, "Organization")
	if err != nil {
		logging.Writef("NewSysMessage: unable to obtain keycard for recipient %s's organization: %s",
			recipient.AsString(), err.Error())
		return out, err
	}
	rawOrgKeyString := recipientOrgCard.Entries[len(recipientOrgCard.Entries)-1].Fields["Encryption-Key"]
	var orgKeyString ezn.CryptoString
	err = orgKeyString.Set(rawOrgKeyString)
	if err != nil {
		logging.Writef("NewSysMessage: error setting encryption key for recipient %s's organization: %s",
			recipient.AsString(), err.Error())
		return out, err
	}
	orgKey := ezn.NewEncryptionKey(orgKeyString)

	userCard, err := kcresolver.GetKeycard(maddr, "User")
	if err != nil {
		logging.Writef("NewSysMessage: unable to obtain keycard for recipient %s: %s",
			recipient.AsString(), err.Error())
		return out, err
	}

	rawUserKeyString := userCard.Entries[len(userCard.Entries)-1].Fields["Encryption-Key"]
	var userKeyString ezn.CryptoString
	err = userKeyString.Set(rawUserKeyString)
	if err != nil {
		logging.Writef("NewSysMessage: error setting encryption key for recipient %s: %s",
			recipient.AsString(), err.Error())
		return out, err
	}
	userKey := ezn.NewEncryptionKey(userKeyString)

	var msg SealedSysEnvelope
	msg.Type = "sysmessage"
	msg.Subtype = msgType
	msg.Version = "1.0"

	receiver := RecipientInfo{
		To:           recipient.AsString(),
		SenderDomain: config.GServerDomain.AsString(),
	}
	rawJSON, err := json.Marshal(receiver)
	if err != nil {
		logging.Writef("NewSysMessage: unable to marshal receiver info: %s", err.Error())
		return out, err
	}
	msg.Receiver, err = orgKey.Encrypt([]byte(rawJSON))
	if err != nil {
		logging.Writef("NewSysMessage: unable to encrypt receiver info: %s", err.Error())
		return out, err
	}

	sender := SenderInfo{
		From:            config.GServerAddress.AsString(),
		RecipientDomain: recipient.GetDomain(),
	}
	rawJSON, err = json.Marshal(sender)
	if err != nil {
		logging.Writef("NewSysMessage: unable to marshal sender info: %s", err.Error())
		return out, err
	}
	msg.Sender, err = sendingServerPair.Encrypt([]byte(rawJSON))
	if err != nil {
		logging.Writef("NewSysMessage: unable to encrypt sender info: %s", err.Error())
		return out, err
	}

	msg.Date = now.Format("20060102T030405Z")

	// PayloadKey
	msgKey := ezn.GenerateSecretKey(ezn.PreferredSecretType())
	encPayloadKey, err := userKey.Encrypt(msgKey.Key.RawData())
	if err != nil {
		logging.Writef("NewSysMessage: unable to encrypt payload key for recipient %s: %s",
			recipient.AsString(), err.Error())
		return out, err
	}
	msg.PayloadKey = encPayloadKey
	out.Envelope = msg

	var payload MsgBody
	payload.From = config.GServerAddress.AsString()
	payload.To = recipient.AsString()
	payload.Date = msg.Date
	payload.ThreadID = types.RandomIDString()
	payload.Subject = subject
	payload.Body = body

	rawJSON, err = json.Marshal(payload)
	if err != nil {
		logging.Writef("NewSysMessage: unable to marshal payload for recipient %s: %s",
			recipient.AsString(), err.Error())
		return out, err
	}

	encryptedPayload, err := msgKey.Encrypt(rawJSON)
	if err != nil {
		logging.Writef("NewSysMessage: unable to encrypt payload for recipient %s: %s",
			recipient.AsString(), err.Error())
		return out, err
	}
	out.Payload = ezn.NewCS(encryptedPayload)

	return out, nil
}
