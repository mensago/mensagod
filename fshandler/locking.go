package fshandler

import "sync"

type FileLock struct {
	WorkerID  uint64
	Timestamp string
	Filename  string
}

type LockList struct {
	ListLock  sync.RWMutex
	LockItems map[uint64]bool
}

// NewLockList creates a new file locking list
func NewLockList() *LockList {
	var out LockList
	out.LockItems = make(map[uint64]bool)
	return &out
}

func (ll *LockList) LockFile(filename string, owner uint64) bool {

	// TODO: Finish implementing LockList.LockFile
	return false
}
