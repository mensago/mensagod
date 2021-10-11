package fshandler

import (
	"testing"
	"time"
)

func LockTestSecondThread(filename string) {
	RLockFile(filename)
	time.Sleep(time.Millisecond * 500)
	RUnlockFile(filename)
}

func TestLocking(t *testing.T) {

	filename := "12345.1000.11111111-1111-1111-1111-111111111111"
	go LockTestSecondThread(filename)
	time.Sleep(time.Millisecond * 100)

	// Subtest #1: IsLocked()
	if locked, _ := IsFileLocked(filename); !locked {
		t.Fatal("TestLocking: IsLocked() subtest failure")
	}
}
