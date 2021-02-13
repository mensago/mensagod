package fshandler

import (
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

// GenerateRandomFile creates a random file filled with zeroes which can be as small as 100 bytes
// and as large as 10k
func generateRandomFile(dir string, size int) (string, error) {
	if size > 10240 || size < 100 {
		return "", errors.New("Size out of range")
	}

	filedata := make([]byte, size, size)
	for j := range filedata {
		filedata[j] = 48
	}
	filename := GenerateFileName(size)

	path := filepath.Join(dir, filename)
	err := ioutil.WriteFile(path, filedata, 0777)
	if err != nil {
		return "", err
	}
	fmt.Printf("Wrote file %s\n", filename)

	return filename, nil
}

func makeTestFiles(dir string, count int) error {
	if count > 50 || count < 1 {
		return errors.New("File count out of range")
	}

	for i := 0; i < count; i++ {
		filesize := rand.Intn(10140) + 100
		generateRandomFile("C:\\ProgramData\\anselus", filesize)
		time.Sleep(time.Millisecond * 500)
	}
	return nil
}

// MakeTestDirectories creates a number of randomly-named directories and returns their names
func makeTestDirectories(path string, count int) ([]string, error) {
	if count > 50 || count < 1 {
		return nil, errors.New("Count out of range")
	}

	names := make([]string, count)
	for i := 0; i < count; i++ {
		dirname := uuid.New().String()
		dirpath := filepath.Join(path, dirname)
		err := os.Mkdir(dirpath, 0777)
		if err != nil {
			return nil, err
		}
	}
	return names, nil
}

func TestLocalFSProvider_Exists(t *testing.T) {
}

func TestLocalFSProvider_MakeDirectory(t *testing.T) {
}

func TestLocalFSProvider_RemoveDirectory(t *testing.T) {
}

func TestLocalFSProvider_ListFiles(t *testing.T) {
}

func TestLocalFSProvider_ListDirectories(t *testing.T) {
}

func TestLocalFSProvider_MakeTempFile(t *testing.T) {
}

func TestLocalFSProvider_InstallTempFile(t *testing.T) {
}

func TestLocalFSProvider_MoveFile(t *testing.T) {
}

func TestLocalFSProvider_CopyFile(t *testing.T) {
}

func TestLocalFSProvider_DeleteFile(t *testing.T) {
}

func TestLocalFSProvider_OpenFile(t *testing.T) {
}

func TestLocalFSProvider_ReadFile(t *testing.T) {
}

func TestLocalFSProvider_CloseFile(t *testing.T) {
}
