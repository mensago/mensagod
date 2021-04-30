package delivery

import (
	"container/list"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"sync"

	"github.com/darkwyrm/mensagod/dbhandler"
	"github.com/darkwyrm/mensagod/fshandler"
	"github.com/darkwyrm/mensagod/logging"
	"github.com/spf13/viper"
)

type messageInfo struct {
	Sender    string
	Recipient string
	Path      string
}

var messageQueue *list.List
var queueLock sync.Mutex
var workerCount int
var workerGroup sync.WaitGroup
var maxWorkers int
var workerLock sync.Mutex
var quitFlag bool
var quitLock sync.RWMutex

type SealedEnvelope struct {
	Type       string
	Version    string
	Recipient  string
	Sender     string
	Date       string
	PayloadKey string
	Payload    string
}

type Envelope struct {
	Type       string
	Version    string
	Recipient  RecipientInfo
	Sender     SenderInfo
	Date       string
	PayloadKey string
	Payload    MsgBody
}

type RecipientInfo struct {
	// To contains the full recipient address
	To string

	// Sender contains only the domain of origin
	Sender string
}

type SenderInfo struct {
	// From contains the full sender address
	From string

	// Receiver contains only the destination's domain
	Receiver string
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

func Init() {
	messageQueue = list.New()
	maxWorkers = viper.GetInt("performance.max_delivery_threads")
}

func Shutdown() {
	quitLock.Lock()
	quitFlag = true
	quitLock.Unlock()
	workerGroup.Wait()
}

// PushMessage enqueues a message for delivery
func PushMessage(sender string, recipientDomain string, path string) {
	info := messageInfo{Sender: sender, Recipient: recipientDomain, Path: path}
	queueLock.Lock()
	messageQueue.PushBack(info)
	queueLock.Unlock()

	workerLock.Lock()
	if workerCount < maxWorkers {
		workerCount++
		workerGroup.Add(1)
		go deliveryWorker()
	}
	workerLock.Unlock()
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
	for {
		quitLock.RLock()
		if quitFlag {
			quitLock.RUnlock()
			break
		}
		quitLock.RUnlock()

		msgInfo := popMessage()
		if msgInfo == nil {
			break
		}

		localPath := fshandler.ConvertToLocal(msgInfo.Path)
		_, err := os.Stat(localPath)
		if err != nil {
			continue
		}

		// The Recipient field will contain a domain, not a full address
		isLocal, err := dbhandler.IsDomainLocal(msgInfo.Recipient)
		if err != nil {
			logging.Writef("Error getting domain %s: %s", msgInfo.Recipient, err)
			continue
		}

		if isLocal {
			// TODO: Local Delivery
			// - Load file and decrypt recipient information
			// - Get workspace ID from recipient information and move file to the /new directory for
			//		the recipient
			// - Check if workspace has any active client connections. If it does, send an update
			//		message to the client workers that there is a new message
		}

		// External Delivery is not needed for demo completeness. Instead we will delete the
		// message and push a bounce message into the sender's workspace for now.

		// TODO: implement External Delivery
	}

	workerLock.Lock()
	workerCount--
	workerGroup.Done()
	workerLock.Unlock()
}

// DecryptRecipient assumes that the file passed to it has a recipient section which can be
// decrypted by the servers Primary Encryption Key. This implies that the server is the
// destination for the message, so it returns the workspace ID of the recipient.
func DecryptRecipientHeader(localPath string) (string, error) {
	rawData, err := ioutil.ReadFile(localPath)
	if err != nil {
		return "", err
	}

	var out SealedEnvelope
	err = json.Unmarshal(rawData, &out)
	if err != nil {
		return "", errors.New("unmarshalling failure")
	}

	return "", errors.New("unimplemented")
}
