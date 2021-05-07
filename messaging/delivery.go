package messaging

import (
	"container/list"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/darkwyrm/mensagod/dbhandler"
	"github.com/darkwyrm/mensagod/fshandler"
	"github.com/darkwyrm/mensagod/logging"
	"github.com/spf13/viper"
)

var messageQueue *list.List
var queueLock sync.Mutex
var workerCount int
var workerGroup sync.WaitGroup
var maxWorkers int
var workerLock sync.Mutex
var quitFlag bool
var quitLock sync.RWMutex

type messageInfo struct {
	Sender    string
	Recipient string
	Path      string
}

func InitDelivery() {
	messageQueue = list.New()
	maxWorkers = viper.GetInt("performance.max_delivery_threads")
}

func ShutdownDelivery() {
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
			// TODO: Bounce (internal server error)
			continue
		}

		// The Recipient field will contain a domain, not a full address
		isLocal, err := dbhandler.IsDomainLocal(msgInfo.Recipient)
		if err != nil {
			// TODO: Bounce (internal server error)
			continue
		}

		if isLocal {
			recipient, err := DecryptRecipientHeader(msgInfo.Path)
			if err != nil {
				// TODO: Bounce (unreadable recipient header for local delivery)
				continue
			}

			parts := strings.SplitN(recipient, "/", 1)
			if !dbhandler.ValidateUUID(parts[0]) {
				// TODO: Bounce (bad recipient workspace)
				continue
			}

			destNew := fshandler.ConvertToLocal("/ " + parts[0] + " new")
			_, err = os.Stat(destNew)
			if err != nil {
				err = os.MkdirAll(destNew, 0600)
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

	var env SealedEnvelope
	err = json.Unmarshal(rawData, &env)
	if err != nil {
		return "", errors.New("unmarshalling failure")
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
		return "", errors.New("unmarshalling failure")
	}

	return out.To, nil
}
