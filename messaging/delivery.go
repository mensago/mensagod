package messaging

import (
	"bufio"
	"container/list"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"
	ezn "gitlab.com/darkwyrm/goeznacl"
	"gitlab.com/mensago/mensagod/dbhandler"
	"gitlab.com/mensago/mensagod/fshandler"
	"gitlab.com/mensago/mensagod/logging"
	"gitlab.com/mensago/mensagod/misc"
	"gitlab.com/mensago/mensagod/types"
	"gitlab.com/mensago/mensagod/workerpool"
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
	deliveryPool = workerpool.New(viper.GetUint("performance.max_delivery_threads"))
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

	if id, ok := deliveryPool.Add(); ok {
		go deliveryWorker(id)
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

func deliveryWorker(workerID uint64) {
	defer deliveryPool.Done(workerID)

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
		domain, err := types.ToDomain(msgInfo.Receiver)
		if err != nil {
			Bounce(300, msgInfo, &map[string]string{"INTERNALCODE": "messaging.deliveryWorker.2"})
			continue
		}

		isLocal, err := dbhandler.IsDomainLocal(domain)
		if err != nil {
			Bounce(300, msgInfo, &map[string]string{"INTERNALCODE": "messaging.deliveryWorker.3"})
			continue
		}

		if isLocal {
			sEnv, err := ReadMessageHeader(localPath)
			if err != nil {
				Bounce(300, msgInfo, &map[string]string{"INTERNALCODE": "messaging.deliveryWorker.4"})
				continue
			}

			recipient, err := DecryptRecipientHeader(sEnv.Receiver)
			if err != nil {
				Bounce(504, msgInfo, nil)
				continue
			}

			parts := strings.Split(recipient, "/")
			if !dbhandler.ValidateUUID(parts[0]) {
				Bounce(503, msgInfo, &map[string]string{"RECIPIENTADDRESS": parts[0]})
				continue
			}

			destNew := fshandler.ConvertToLocal("/ wsp " + parts[0] + " new")
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
				ID:       types.RandomIDString(),
				Type:     dbhandler.UpdateCreate,
				Data:     strings.Join([]string{"/", "wsp", parts[0], "new", basename}, " "),
				Time:     timestamp,
				DeviceID: "00000000-0000-0000-0000-000000000000",
			})

			if IsWorkspaceRegistered(parts[0]) {
				UpdateWorkspace(parts[0], timestamp)
			}

			// Finish processing a local delivery
			continue
		}

		// TODO: POSTDEMO: implement External Delivery

		// External Delivery is not needed for demo completeness. Instead we will delete the
		// message and push a bounce message into the sender's workspace for now.
		Bounce(301, msgInfo, nil)
		os.Remove(msgInfo.Path)
	}
}

// ReadMessageHeader loads from a file the message data up to, but not including, the payload
// and returns a SealedEnvelope instance so that it may be processed for delivery
func ReadMessageHeader(localPath string) (SealedEnvelope, error) {
	var out SealedEnvelope

	fHandle, err := os.Open(localPath)
	if err != nil {
		return out, err
	}
	defer fHandle.Close()

	reader := bufio.NewReader(fHandle)

	// Skip over the first couple lines
	for {
		rawLine, err := reader.ReadString('\n')
		if err != nil {
			return out, errors.New("invalid message file format")
		}
		if strings.TrimSpace(rawLine) == "MENSAGO" {
			break
		}
	}

	// Read in all of the header, line by line
	headerLines := make([]string, 0)
	for {
		rawLine, err := reader.ReadString('\n')
		if err != nil {
			return out, errors.New("invalid message file format")
		}
		trimLine := strings.TrimSpace(rawLine)
		if trimLine == "----------" {
			break
		}
		headerLines = append(headerLines, trimLine)
	}

	err = json.Unmarshal([]byte(strings.Join(headerLines, "")), &out)
	if err != nil {
		return out, err
	}

	return out, nil
}

// DecryptRecipient assumes that the file passed to it has a recipient section which can be
// decrypted by the servers Primary Encryption Key. This implies that the server is the
// destination for the message, so it returns the workspace ID of the recipient.
func DecryptRecipientHeader(header string) (string, error) {

	encPair, err := dbhandler.GetEncryptionPair()
	if err != nil {
		return "", err
	}

	encData := ezn.NewCS(header)
	if !encData.IsValid() {
		return "", ezn.ErrInvalidCS
	}

	decrypted, err := encPair.Decrypt(encData.Data)
	if err != nil {
		return "", err
	}

	var out RecipientInfo
	err = json.Unmarshal(decrypted, &out)
	if err != nil {
		return "", misc.ErrJSONUnmarshal
	}

	return out.To, nil
}

// Bounce() is used to send delivery reports to local users
func Bounce(errorCode int, info *messageInfo, extraData *map[string]string) {

	subject := ""
	body := ""
	switch errorCode {
	case 300:
		subject = "Delivery Report: Internal Server Error"
		internalCode, exists := (*extraData)["INTERNALCODE"]
		if exists {
			body = strings.Replace(bounce300Body, "%INTERNALCODE%", internalCode, 1)
		} else {
			body = bounce300Body
		}
	case 503:
		subject = "Delivery Report: Bad Recipient Address"
		recipientAddress, exists := (*extraData)["RECIPIENTADDRESS"]
		if exists {
			body = strings.Replace(bounce300Body, "%RECIPIENTADDRESS%", recipientAddress, 1)
		} else {
			body = bounce503Body
		}
	case 504:
		subject = "Delivery Report: Unreadable Recipient Address"
		body = bounce504Body
	case 301:
		subject = "Delivery Report: External Delivery Not Implemented"
		body = bounce301Body
	default:
		logging.Writef("Bounce: unhandled error code %d", errorCode)
		return
	}

	msg, err := NewSysMessage("deliveryreport", info, subject, body)
	if err != nil {
		logging.Writef("Bounce: error creating system message for %s: %s", info.Sender,
			err.Error())
		return
	}

	rawJSON, err := json.Marshal(msg.Envelope)
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
			msg.Payload,
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
		ID:       types.RandomIDString(),
		Type:     dbhandler.UpdateCreate,
		Data:     strings.Join([]string{"/", "wsp", parts[0], "new", msgFileName}, " "),
		Time:     timestamp,
		DeviceID: "00000000-0000-0000-0000-000000000000",
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
