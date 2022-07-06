package fshandler

import (
	"sync"

	"gitlab.com/mensago/mensagod/misc"
)

var lockList sync.Map

func RLockFile(filename string) error {

	if filename == "" {
		return misc.ErrBadArgument
	}

	var newLock sync.RWMutex
	fLock, loaded := lockList.LoadOrStore(filename, &newLock)
	if loaded {
		fLock.(*sync.RWMutex).RLock()
	} else {
		newLock.RLock()
	}

	return nil
}

func LockFile(filename string) error {

	if filename == "" {
		return misc.ErrBadArgument
	}

	var newLock sync.RWMutex
	fLock, loaded := lockList.LoadOrStore(filename, &newLock)
	if loaded {
		fLock.(*sync.RWMutex).Lock()
	} else {
		newLock.Lock()
	}

	return nil
}

func RUnlockFile(filename string) error {

	if filename == "" {
		return misc.ErrBadArgument
	}

	fLock, loaded := lockList.Load(filename)
	if loaded {
		fLock.(*sync.RWMutex).RUnlock()
	}

	return nil
}

func UnlockFile(filename string) error {

	if filename == "" {
		return misc.ErrBadArgument
	}

	fLock, loaded := lockList.Load(filename)
	if loaded {
		fLock.(*sync.RWMutex).Unlock()
	}

	return nil
}

func IsFileLocked(filename string) (bool, error) {

	if filename == "" {
		return false, misc.ErrBadArgument
	}

	_, loaded := lockList.Load(filename)

	return loaded, nil
}
