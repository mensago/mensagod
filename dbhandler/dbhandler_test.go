package dbhandler

import (
	"errors"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/darkwyrm/anselusd/config"
	"github.com/darkwyrm/anselusd/fshandler"
	"github.com/google/uuid"
)

// setupTest initializes the global config and resets the database
func setupTest() error {

	// In this case we don't care about the diceware wordlist returned. Note that
	// resetDatabase depends on initialization of the server config, so this call must go
	// first
	config.SetupConfig()

	Connect()
	if err := resetDatabase(); err != nil {
		return err
	}

	return nil
}

// resetDatabase empties out the workspace directory to make sure it's ready for a filesystem
// test. Because the workspace directory may have special permissions set on it, we can't just
// delete the directory and recreate it--we have to actually empty the directory.
func resetDatabase() error {
	data, err := ioutil.ReadFile("psql_schema.sql")
	if err != nil {
		return err
	}

	_, err = dbConn.Exec(string(data))
	return err
}

// resetWorkspaceDir empties out the workspace directory to make sure it's ready for a filesystem
// test. Because the workspace directory may have special permissions set on it, we can't just
// delete the directory and recreate it--we have to actually empty the directory.
func resetWorkspaceDir() error {
	var anpath fshandler.LocalAnPath
	err := anpath.Set("/")
	if err != nil {
		return err
	}

	handle, err := os.Open(anpath.ProviderPath())
	if err != nil {
		return err
	}
	defer handle.Close()

	entries, err := handle.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		err = os.RemoveAll(filepath.Join(anpath.ProviderPath(), entry))
		if err != nil {
			return err
		}
	}
	return nil
}

// generateRandomFile creates a random file filled with zeroes which can be as small as 100 bytes
// and as large as 10k
func generateRandomFile(dir string, size int) (string, error) {
	if size > 10240 || size < 100 {
		return "", errors.New("Size out of range")
	}

	var anpath fshandler.LocalAnPath
	err := anpath.Set(dir)
	if err != nil {
		return "", err
	}

	_, err = os.Stat(anpath.ProviderPath())
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}

	filedata := make([]byte, size, size)
	for j := range filedata {
		filedata[j] = 48
	}
	filename := fshandler.GenerateFileName(size)

	path := filepath.Join(anpath.ProviderPath(), filename)
	err = ioutil.WriteFile(path, filedata, 0777)
	if err != nil {
		return "", err
	}

	return filename, nil
}

func makeTestFiles(dir string, count int) error {
	if count > 50 || count < 1 {
		return errors.New("File count out of range")
	}

	var anpath fshandler.LocalAnPath
	err := anpath.Set(dir)
	if err != nil {
		return err
	}

	_, err = os.Stat(anpath.ProviderPath())
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	for i := 0; i < count; i++ {
		filesize := rand.Intn(10140) + 100
		_, err = generateRandomFile(anpath.AnselusPath(), filesize)
		if err != nil {
			return err
		}
		time.Sleep(time.Millisecond * 500)
	}
	return nil
}

// MakeTestDirectories creates a number of randomly-named directories and returns their names
func makeTestDirectories(path string, count int) ([]string, error) {
	if count > 50 || count < 1 {
		return nil, errors.New("Count out of range")
	}

	var anpath fshandler.LocalAnPath
	err := anpath.Set(path)
	if err != nil {
		return nil, err
	}

	_, err = os.Stat(anpath.ProviderPath())
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	names := make([]string, count)
	for i := 0; i < count; i++ {
		dirname := uuid.New().String()
		dirpath := filepath.Join(anpath.ProviderPath(), dirname)
		err := os.Mkdir(dirpath, 0777)
		if err != nil {
			return nil, err
		}
	}
	return names, nil
}

// ensureTestDirectory makes sure a specific test directory exists. The path is expected to be
// an Anselus-format path, resulting in a path relative to the workspace root.
func ensureTestDirectory(path string) error {
	var anpath fshandler.LocalAnPath
	err := anpath.Set(path)
	if err != nil {
		return err
	}

	_, err = os.Stat(anpath.ProviderPath())
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	return os.Mkdir(anpath.ProviderPath(), 0777)
}

func TestDBHandler_GetQuota(t *testing.T) {
	if err := setupTest(); err != nil {
		t.Fatalf("TestDBHandler_GetQuota: Couldn't reset database: %s", err.Error())
	}
}

func TestDBHandler_GetQuotaUsage(t *testing.T) {
	if err := setupTest(); err != nil {
		t.Fatalf("TestDBHandler_GetQuota: Couldn't reset database: %s", err.Error())
	}
}

// TODO: Tests to write:

// AddDevice
// AddEntry
// AddWorkspace
// CheckDevice
// CheckLockout
// CheckPasscode
// CheckPassword
// CheckRegCode
// CheckUserID
// CheckWorkspace
// DeletePasscode
// DeleteRegCode
// GetAliases
// GetAnselusAddressType
// GetEncryptionPair
// GetLastEntry
// GetOrgEntries
// GetPrimarySigningKey
// GetUserEntries
// IsAlias
// LogFailure
// ModifyQuotaUsage
// PreregWorkspace
// RemoveDevice
// RemoveExpiredPasscodes
// RemoveWorkspace
// ResetPassword
// ResetQuotaUsage
// ResolveAddress
// SetPassword
// SetQuota
// SetQuotaUsage
// SetWorkspaceStatus
// UpdateDevice
