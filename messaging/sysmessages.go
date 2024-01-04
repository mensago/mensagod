package messaging

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/spf13/viper"
	ezn "gitlab.com/darkwyrm/goeznacl"
	"gitlab.com/mensago/mensagod/dbhandler"
	"gitlab.com/mensago/mensagod/kcresolver"
	"gitlab.com/mensago/mensagod/logging"
	"gitlab.com/mensago/mensagod/types"
)

//	{
//	    "Type" : "sysmessage",
//	    "Subtype" : "devrequest",
//	    "Version" : "1.0",
//	    "From" : "mensago-example.com",
//	    "To" : "662679bd-3611-4d5e-a570-52812bdcc6f3/example.com",
//	    "Date" : "2022-05-05T10:07:56Z",
//	    "Format": "text",
//	    "Subject" : "New Device Approval",
//	    "Body" : "Time:2022-05-05T10:07:56Z\r\nExpires:2022-05-05T18:07:56Z\r\nIP:12.80.0.162\r\nLocation:Morristown, New Jersey\r\n",
//	    "Attachments": [{
//	        "Name": "deviceinfo",
//	        "Type": "application/vnd.mensago.encrypted-json",
//	        "Data": "CURVE25519:{UfJ=rOoXjUA-Q$rBMw<70Q{eK&ro?HYKGB$zPtG",
//	    }]
//	}
func NewDeviceApproval(info messageInfo, devid types.RandomID) (*SealedEnvelope, error) {

	return nil, errors.New("NewDeviceApproval unimplemented")
}

// NewSysMessage() is used to create system messages intended for delivery to a local user.
func NewSysMessage(msgType string, info *messageInfo, subject string, body string,
	extraData *map[string]string) (SealedMessage, error) {

	var out SealedMessage

	orgDomain := viper.GetString("global.domain")
	now := time.Now().UTC()
	encPair, err := dbhandler.GetEncryptionPair()
	if err != nil {
		logging.Writef("NewSysMessage: unable to get org encryption pair: %s", err.Error())
		return out, err
	}

	var addr types.MAddress
	err = addr.Set(info.Sender)
	if err != nil {
		logging.Writef("NewSysMessage: invalid sender addres %s", info.Sender)
		return out, err
	}
	userCard, err := kcresolver.GetKeycard(addr, "User")
	if err != nil {
		logging.Writef("NewSysMessage: unable to obtain keycard for sender %s: %s", info.Sender,
			err.Error())
		return out, err
	}

	rawUserKeyString := userCard.Entries[len(userCard.Entries)-1].Fields["Encryption-Key"]
	var userKeyString ezn.CryptoString
	err = userKeyString.Set(rawUserKeyString)
	if err != nil {
		logging.Writef("NewSysMessage: error setting encryption key for sender %s: %s", info.Sender,
			err.Error())
		return out, err
	}
	userKey := ezn.NewEncryptionKey(userKeyString)

	var msg SealedEnvelope
	msg.Type = msgType
	msg.Version = "1.0"

	receiver := RecipientInfo{
		To:           info.Sender,
		SenderDomain: orgDomain,
	}
	rawJSON, err := json.Marshal(receiver)
	if err != nil {
		logging.Writef("NewSysMessage: unable to marshal receiver info: %s", err.Error())
		return out, err
	}
	msg.Receiver, err = encPair.Encrypt([]byte(rawJSON))
	if err != nil {
		logging.Writef("NewSysMessage: unable to encrypt receiver info: %s", err.Error())
		return out, err
	}

	sender := SenderInfo{
		From:            orgDomain,
		RecipientDomain: orgDomain,
	}
	rawJSON, err = json.Marshal(sender)
	if err != nil {
		logging.Writef("NewSysMessage: unable to marshal sender info: %s", err.Error())
		return out, err
	}
	msg.Sender, err = encPair.Encrypt([]byte(rawJSON))
	if err != nil {
		logging.Writef("NewSysMessage: unable to encrypt sender info: %s", err.Error())
		return out, err
	}

	msg.Date = now.Format("20060102T030405Z")

	// PayloadKey
	msgKey := ezn.GenerateSecretKey(ezn.PreferredSecretType())
	encPayloadKey, err := userKey.Encrypt(msgKey.Key.RawData())
	if err != nil {
		logging.Writef("NewSysMessage: unable to encrypt payload key for sender %s: %s", info.Sender,
			err.Error())
		return out, err
	}
	msg.PayloadKey = encPayloadKey
	out.Envelope = msg

	var payload MsgBody
	payload.From = orgDomain
	payload.To = info.Sender
	payload.Date = msg.Date
	payload.ThreadID = types.RandomIDString()
	payload.Subject = subject
	payload.Body = body

	rawJSON, err = json.Marshal(payload)
	if err != nil {
		logging.Writef("NewSysMessage: unable to marshal payload for sender %s: %s", info.Sender,
			err.Error())
		return out, err
	}

	encryptedPayload, err := msgKey.Encrypt(rawJSON)
	if err != nil {
		logging.Writef("NewSysMessage: unable to encrypt payload for sender %s: %s", info.Sender,
			err.Error())
		return out, err
	}
	out.Payload = encryptedPayload

	return out, nil
}
