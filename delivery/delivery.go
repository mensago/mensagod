package delivery

import (
	"container/list"
	"errors"
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
var maxWorkers int

func Init() {
	messageQueue = list.New()
	maxWorkers = viper.GetInt("performance.max_delivery_threads")
}

// PushMessage enqueues a message for delivery
func PushMessage(sender string, recipientDomain string, path string) error {
	info := messageInfo{Sender: sender, Recipient: recipientDomain, Path: path}
	queueLock.Lock()
	messageQueue.PushBack(info)
	queueLock.Unlock()

	return errors.New("unimplemented")
}

// popMessage removes a message from the queue
func popMessage() (*messageInfo, error) {
	var out messageInfo
	queueLock.Lock()
	defer queueLock.Unlock()

	item := messageQueue.Front()
	if item == nil {
		return nil, nil
	}

	out = item.Value.(messageInfo)
	messageQueue.Remove(item)
	return &out, errors.New("unimplemented")
}

func deliveryWorker() {

}
