package messaging

import (
	"container/list"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	cs "github.com/darkwyrm/mensagod/cryptostring"
	"github.com/darkwyrm/mensagod/dbhandler"
	"github.com/darkwyrm/mensagod/ezcrypt"
	"github.com/darkwyrm/mensagod/fshandler"
	"github.com/darkwyrm/mensagod/keycard_cache"
	"github.com/darkwyrm/mensagod/logging"
	"github.com/darkwyrm/mensagod/misc"
	"github.com/darkwyrm/mensagod/types"
	"github.com/darkwyrm/mensagod/workerpool"
	"github.com/google/uuid"
	"github.com/spf13/viper"
)

var messageQueue *list.List
var queueLock sync.Mutex

type messageInfo struct {
	Sender   string
	Receiver string
	Path     string
}

var deliveryPool *workerpool.Pool

func InitDelivery() {
	messageQueue = list.New()
	deliveryPool = workerpool.New(uint(viper.GetInt("performance.max_delivery_threads")))
}

func ShutdownDelivery() {
	deliveryPool.Quit()
}

// PushMessage enqueues a message for delivery
func PushMessage(sender string, recipientDomain string, path string) {
	info := messageInfo{Sender: sender, Receiver: recipientDomain, Path: path}
	queueLock.Lock()
	messageQueue.PushBack(info)
	queueLock.Unlock()

	if deliveryPool.Add(1) > 0 {
		go deliveryWorker()
	}
}

// popMessage removes a message from the queue
func popMessage() *messageInfo {
	var out messageInfo
	queueLock.Lock()
	defer queueLock.Unlock()

	item := messageQueue.Front()
	if item == nil {
		return nil
	}

	out = item.Value.(messageInfo)
	messageQueue.Remove(item)
	return &out
}

func deliveryWorker() {
	defer deliveryPool.Done()

	for {
		if deliveryPool.IsQuitting() {
			break
		}

		msgInfo := popMessage()
		if msgInfo == nil {
			break
		}

		localPath := fshandler.ConvertToLocal(msgInfo.Path)
		_, err := os.Stat(localPath)
		if err != nil {
			Bounce(300, msgInfo, &map[string]string{"INTERNALCODE": "messaging.deliveryWorker.1"})
			continue
		}

		// The Receiver field will contain a domain, not a full address
		isLocal, err := dbhandler.IsDomainLocal(msgInfo.Receiver)
		if err != nil {
			Bounce(300, msgInfo, &map[string]string{"INTERNALCODE": "messaging.deliveryWorker.2"})
			continue
		}

		if isLocal {
			recipient, err := DecryptRecipientHeader(msgInfo.Path)
			if err != nil {
				Bounce(504, msgInfo, nil)
				continue
			}

			parts := strings.SplitN(recipient, "/", 1)
			if !dbhandler.ValidateUUID(parts[0]) {
				Bounce(503, msgInfo, &map[string]string{"RECIPIENTADDRESS": parts[0]})
				continue
			}

			destNew := fshandler.ConvertToLocal("/ " + parts[0] + " new")
			_, err = os.Stat(destNew)
			if err != nil {
				err = os.MkdirAll(destNew, 0770)
				if err != nil {
					logging.Writef("Unable to create directory %s: %s", destNew, err)
					continue
				}
			}

			basename := filepath.Base(localPath)
			err = os.Rename(localPath, filepath.Join(destNew, basename))
			if err != nil {
				logging.Writef("Unable to move file %s to %s: %s", localPath, destNew, err)
				continue
			}

			timestamp := time.Now().UTC().Unix()
			dbhandler.AddSyncRecord(parts[0], dbhandler.UpdateRecord{
				Type: dbhandler.UpdateAdd,
				Data: strings.Join([]string{"/", parts[0], "new", basename}, " "),
				Time: timestamp,
			})

			if IsWorkspaceRegistered(parts[0]) {
				UpdateWorkspace(parts[0], timestamp)
			}
		}

		// TODO: POSTDEMO: implement External Delivery

		// External Delivery is not needed for demo completeness. Instead we will delete the
		// message and push a bounce message into the sender's workspace for now.
		Bounce(301, msgInfo, nil)
		os.Remove(msgInfo.Path)
	}
}

// DecryptRecipient assumes that the file passed to it has a recipient section which can be
// decrypted by the servers Primary Encryption Key. This implies that the server is the
// destination for the message, so it returns the workspace ID of the recipient.
func DecryptRecipientHeader(localPath string) (string, error) {
	rawData, err := ioutil.ReadFile(localPath)
	if err != nil {
		return "", err
	}

	var env SealedEnvelope
	err = json.Unmarshal(rawData, &env)
	if err != nil {
		return "", misc.ErrJSONUnmarshal
	}

	encPair, err := dbhandler.GetEncryptionPair()
	if err != nil {
		return "", err
	}

	decrypted, err := encPair.Decrypt(env.Receiver)
	if err != nil {
		return "", err
	}

	var out RecipientInfo
	err = json.Unmarshal(decrypted, &env)
	if err != nil {
		return "", misc.ErrJSONUnmarshal
	}

	return out.To, nil
}

// Bounce() is used to send delivery reports to local users
func Bounce(errorCode int, info *messageInfo, extraData *map[string]string) {

	orgDomain := viper.GetString("global.domain")
	now := time.Now().UTC()
	encPair, err := dbhandler.GetEncryptionPair()
	if err != nil {
		logging.Writef("Bounce: unable to get org encryption pair: %s", err.Error())
		return
	}

	var addr types.Address
	err = addr.Set(info.Sender)
	if err != nil {
		logging.Writef("Bounce: invalid sender addres %s", info.Sender)
		return
	}
	userCard, err := keycard_cache.GetKeycard(addr, "User")
	if err != nil {
		logging.Writef("Bounce: unable to obtain keycard for sender %s: %s", info.Sender,
			err.Error())
		return
	}

	rawUserKeyString := userCard.Entries[len(userCard.Entries)-1].Fields["Encryption-Key"]
	var userKeyString cs.CryptoString
	err = userKeyString.Set(rawUserKeyString)
	if err != nil {
		logging.Writef("Bounce: error setting encryption key for sender %s: %s", info.Sender,
			err.Error())
		return
	}
	userKey := ezcrypt.NewEncryptionKey(userKeyString)

	var msg SealedEnvelope
	msg.Type = "deliveryreport"
	msg.Version = "1.0"

	receiver := RecipientInfo{
		To:           info.Sender,
		SenderDomain: orgDomain,
	}
	rawJSON, err := json.Marshal(receiver)
	if err != nil {
		logging.Writef("Bounce: unable to marshal receiver info: %s", err.Error())
		return
	}
	msg.Receiver, err = encPair.Encrypt([]byte(rawJSON))
	if err != nil {
		logging.Writef("Bounce: unable to encrypt receiver info: %s", err.Error())
		return
	}

	sender := SenderInfo{
		From:            orgDomain,
		RecipientDomain: orgDomain,
	}
	rawJSON, err = json.Marshal(sender)
	if err != nil {
		logging.Writef("Bounce: unable to marshal sender info: %s", err.Error())
		return
	}
	msg.Sender, err = encPair.Encrypt([]byte(rawJSON))
	if err != nil {
		logging.Writef("Bounce: unable to encrypt sender info: %s", err.Error())
		return
	}

	msg.Date = now.Format("20060102T030405Z")

	// PayloadKey
	msgKey := ezcrypt.GenerateSymmetricKey()
	encPayloadKey, err := userKey.Encrypt(msgKey.Key.RawData())
	if err != nil {
		logging.Writef("Bounce: unable to encrypt payload key for sender %s: %s", info.Sender,
			err.Error())
		return
	}
	msg.PayloadKey = encPayloadKey

	var payload MsgBody
	payload.From = orgDomain
	payload.To = info.Sender
	payload.Date = msg.Date
	payload.ThreadID = uuid.New().String()

	switch errorCode {
	case 300:
		payload.Subject = "Delivery Report: Internal Server Error"
		internalCode, exists := (*extraData)["INTERNALCODE"]
		if exists {
			payload.Body = strings.Replace(bounce300Body, "%INTERNALCODE%", internalCode, 1)
		} else {
			payload.Body = bounce300Body
		}
	case 503:
		payload.Subject = "Delivery Report: Bad Recipient Address"
		recipientAddress, exists := (*extraData)["RECIPIENTADDRESS"]
		if exists {
			payload.Body = strings.Replace(bounce300Body, "%RECIPIENTADDRESS%", recipientAddress, 1)
		} else {
			payload.Body = bounce503Body
		}
	case 504:
		payload.Subject = "Delivery Report: Unreadable Recipient Address"
		payload.Body = bounce504Body
	case 301:
		payload.Subject = "Delivery Report: External Delivery Not Implemented"
		payload.Body = bounce301Body
	default:
		logging.Writef("Bounce: unhandled error code %d", errorCode)
		return
	}

	payload.Body = strings.Replace(payload.Body, "%TIMESTAMP%",
		time.Now().UTC().Format("2006-01-02 03:04:05"), 1)
	rawJSON, err = json.Marshal(payload)
	if err != nil {
		logging.Writef("Bounce: unable to marshal payload for sender %s: %s", info.Sender,
			err.Error())
		return
	}

	encryptedPayload, err := msgKey.Encrypt(rawJSON)
	if err != nil {
		logging.Writef("Bounce: unable to encrypt payload for sender %s: %s", info.Sender,
			err.Error())
		return
	}

	rawJSON, err = json.Marshal(msg)
	if err != nil {
		logging.Writef("Bounce: unable to marshal message for sender %s: %s", info.Sender,
			err.Error())
		return
	}

	fsp := fshandler.GetFSProvider()
	handle, tempName, err := fsp.MakeTempFile(info.Sender)
	if err != nil {
		logging.Writef("Bounce: unable to create temp file for message for sender %s: %s",
			info.Sender, err.Error())
		return
	}
	handle.WriteString(strings.Join(
		[]string{
			string(rawJSON), "\r\n",
			"----------\r\n",
			"XSALSA20\r\n",
			encryptedPayload,
		}, ""))
	handle.Close()

	msgFileName, err := fsp.InstallTempFile(info.Sender, tempName, "/ "+info.Sender+" new")
	if err != nil {
		logging.Writef("Bounce: unable to install temp file for sender %s: %s",
			info.Sender, err.Error())
		return
	}

	parts := strings.SplitN(info.Sender, "/", 1)
	timestamp := time.Now().UTC().Unix()
	dbhandler.AddSyncRecord(parts[0], dbhandler.UpdateRecord{
		Type: dbhandler.UpdateAdd,
		Data: strings.Join([]string{"/", parts[0], "new", msgFileName}, " "),
		Time: timestamp,
	})

	if IsWorkspaceRegistered(parts[0]) {
		UpdateWorkspace(parts[0], timestamp)
	}
}

const bounce300Body string = `The server was unable to deliver your message because of an internal error. Please contact technical support for your account with the information provided below.

----------
Technical Support Information
Error Code: 300 INTERNAL SERVER ERROR
Internal Error Code: %INTERNALCODE%
Date: %TIMESTAMP%
`

const bounce503Body string = `The server was unable to deliver your message because the recipient's address was formatted incorrectly.

----------
Technical Support Information
Error Code: 503 BAD RECIPIENT ADDRESS
Recipent Address: %RECIPIENTADDRESS%
Date: %TIMESTAMP%
`

const bounce504Body string = `The server was unable to deliver your message because it was unable to decrypt the recipient's address. This might be a problem with your program.

----------
Technical Support Information
Error Code: 504 UNREADABLE RECIPIENT ADDRESS
Date: %TIMESTAMP%
`

const bounce301Body string = `The server was unable to deliver your message because external delivery is not yet implemented. Sorry!`
