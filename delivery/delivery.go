package delivery

import (
	"container/list"
	"sync"

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

		// Delivery Handling
		// - get an item from the queue
		// - check the path and ensure file exists. The internal data structure will have been
		//		verified when the file was uploaded for delivery
		// - check the destination domain. Follow the appropriate protocol below based on its
		//		destination

		// Internal Delivery
		// - Load file and decrypt recipient information
		// - Get workspace ID from recipient information and move file to the /new directory for
		//		the recipient
		// - Check if workspace has any active client connections. If it does, send an update
		//		message to the client workers that there is a new message

		// External Delivery
		// - Connect to external server using SERVERID. TL;DR: sending and receiving servers get
		//		PEK from each other's DNS record and use random encrypted challenges to mutually
		//		authenticate.

		//		- Sending server gets receiving server's PEK from its DNS record
		//		- Sender generates receiver challenge and encrypts it with receiver's PEK
		//		- Sender issues SERVERID command with receiver's encrypted challenge and desired
		//			recipient domain
		// 		- Receiver gets PEK from sending server's DNS record
		//		- Receiver generates sender challenge and encrypts it with sender's PEK
		//		- Receiver descrypts its own challenge and attaches it and the sender's encrypted
		//			challenge to the response
		//		- Sender confirms the receiver's successful response
		//		- Sender decrypts the receiver's challenge, attaches the decrypted response, and
		//			sends it to the receiver
		//		- Receiver confirm's sender's successful decryption
		//		- Receiver notifies sender is authenticated. Sender may proceed.
		// - Sender issues DELIVER command and uploads message
		// - Receiver decrypts sender information and returns appropriate delivery response code
	}

	workerLock.Lock()
	workerCount--
	workerGroup.Done()
	workerLock.Unlock()
}
