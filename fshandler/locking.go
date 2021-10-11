package fshandler

import (
	"sync"

	"github.com/darkwyrm/mensagod/misc"
)

type FileLock struct {
	Lock     sync.Locker
	Filename string
}

var LockList sync.Map

func RLockFile(filename string) error {

	if filename == "" {
		return misc.ErrBadArgument
	}

	var newLock sync.RWMutex
	fLock, loaded := LockList.LoadOrStore(filename, &newLock)
	if loaded {
		fLock.(*sync.RWMutex).RLock()
	} else {
		newLock.RLock()
	}

	return nil
}

func RWLockFile(filename string) error {

	if filename == "" {
		return misc.ErrBadArgument
	}

	var newLock sync.RWMutex
	fLock, loaded := LockList.LoadOrStore(filename, &newLock)
	if loaded {
		fLock.(*sync.RWMutex).Lock()
	} else {
		newLock.Lock()
	}

	return nil
}

func UnlockFile(filename string) error {

	if filename == "" {
		return misc.ErrBadArgument
	}

	fLock, loaded := LockList.Load(filename)
	if loaded {
		fLock.(*sync.RWMutex).Lock()
	}

	return nil
}

func IsFileLocked(filename string) (bool, error) {

	if filename == "" {
		return false, misc.ErrBadArgument
	}

	_, loaded := LockList.Load(filename)

	return loaded, nil
}
