package dbhandler

import (
	"database/sql"
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
	"github.com/spf13/viper"
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

	wid := "11111111-1111-1111-1111-111111111111"
	ensureTestDirectory("/ " + wid)

	row := dbConn.QueryRow(`SELECT quota FROM quotas WHERE wid=$1`, wid)
	var tempSize int64
	err := row.Scan(&tempSize)

	if err != sql.ErrNoRows {
		t.Fatalf("TestDBHandler_GetQuota: Pre-execution error: %s", err)
	}

	// Subtest #1: Handle nonexistent record
	quotaSize, err := GetQuota(wid)
	if err != nil {
		t.Fatalf("TestDBHandler_GetQuota: #1: failure to get quota: %s", err)
	}
	if quotaSize != uint64(viper.GetInt64("global.default_quota")) {
		t.Fatalf("TestDBHandler_GetQuota: #1: quota wrong size: %d", quotaSize)
	}

	row = dbConn.QueryRow(`SELECT quota FROM quotas WHERE wid=$1`, wid)
	err = row.Scan(&tempSize)
	if err != nil {
		t.Fatalf("TestDBHandler_GetQuota: #1: failed to get quota: %s", err)
	}
	if tempSize != viper.GetInt64("global.default_quota")*0x10_0000 {
		t.Fatalf("TestDBHandler_GetQuota: #1: got the wrong quota size: %d", tempSize)
	}

	// Subtest #2: Get existing record
	err = SetQuota(wid, 0x60_0000)
	if err != nil {
		t.Fatalf("TestDBHandler_GetQuota: #2: failure to update quota size: %s", err)
	}

	quotaSize, err = GetQuota(wid)
	if err != nil {
		t.Fatalf("TestDBHandler_GetQuota: #2: failure to get quota: %s", err)
	}
	if quotaSize != 0x60_0000 {
		t.Fatalf("TestDBHandler_GetQuota: #2: quota wrong size: %d", quotaSize)
	}
}

func TestDBHandler_GetQuotaUsage(t *testing.T) {
	if err := setupTest(); err != nil {
		t.Fatalf("TestDBHandler_GetQuotaUsage: Couldn't reset database: %s", err.Error())
	}

	resetWorkspaceDir()

	wid := "11111111-1111-1111-1111-111111111111"
	testPath := "/ " + wid
	ensureTestDirectory(testPath)
	generateRandomFile(testPath, 2000)

	row := dbConn.QueryRow(`SELECT usage FROM quotas WHERE wid=$1`, wid)
	var tempSize int64
	err := row.Scan(&tempSize)

	if err != sql.ErrNoRows {
		t.Fatalf("TestDBHandler_GetQuotaUsage: Pre-execution error: %s", err)
	}

	// Subtest #1: Handle nonexistent record

	usage, err := GetQuotaUsage(wid)
	if err != nil {
		t.Fatalf("TestDBHandler_GetQuotaUsage: #1: failure to get usage: %s", err)
	}
	if usage != 2000 {
		t.Fatalf("TestDBHandler_GetQuotaUsage: #1: usage wrong size: %d", usage)
	}

	row = dbConn.QueryRow(`SELECT usage FROM quotas WHERE wid=$1`, wid)
	err = row.Scan(&tempSize)
	if err != nil {
		t.Fatalf("TestDBHandler_GetQuota: #1: failed to get usage: %s", err)
	}
	if tempSize != 2000 {
		t.Fatalf("TestDBHandler_GetQuotaUsage: #1: got the wrong usage size: %d", tempSize)
	}

	// Subtest #2: Get existing record

	err = SetQuotaUsage(wid, 3000)
	if err != nil {
		t.Fatalf("TestDBHandler_GetQuotaUsage: #2: failure to update usage: %s", err)
	}

	usage, err = GetQuotaUsage(wid)
	if err != nil {
		t.Fatalf("TestDBHandler_GetQuotaUsage: #2: failure to get usage: %s", err)
	}
	if usage != 3000 {
		t.Fatalf("TestDBHandler_GetQuotaUsage: #2: usage wrong size: %d", usage)
	}
}

func TestDBHandler_ModifyQuotaUsage(t *testing.T) {
	if err := setupTest(); err != nil {
		t.Fatalf("TestDBHandler_ModifyQuotaUsage: Couldn't reset database: %s", err.Error())
	}

	resetWorkspaceDir()

	wid := "11111111-1111-1111-1111-111111111111"
	ensureTestDirectory("/ " + wid)
	generateRandomFile("/ "+wid, 2000)

	row := dbConn.QueryRow(`SELECT usage FROM quotas WHERE wid=$1`, wid)

	var quotaSize int64
	err := row.Scan(&quotaSize)

	if err != sql.ErrNoRows {
		t.Fatalf("TestDBHandler_ModifyQuotaUsage: Pre-execution error: %s", err)
	}

	// Subtest #1: Handle nonexistent record. This means that a new record will be created and the
	// value passed will be ignored. The exact disk usage will be set in the database instead.
	currentUsage, err := ModifyQuotaUsage(wid, 1000)
	if err != nil {
		t.Fatalf("TestDBHandler_ModifyQuotaUsage: #1: failure to update quota: %s", err)
	}
	if currentUsage != 2000 {
		t.Fatalf("TestDBHandler_ModifyQuotaUsage: #1: bad usage value: %d", currentUsage)
	}

	result, err := dbConn.Exec("UPDATE quotas SET usage=-1 WHERE wid=$1", wid)
	if err != nil {
		t.Fatalf("TestDBHandler_ModifyQuotaUsage: #1: failure to reset usage: %s", err)
	}
	rowCount, _ := result.RowsAffected()
	if rowCount != 1 {
		t.Fatalf("TestDBHandler_ModifyQuotaUsage: #1: failure to reset usage: no rows affected")
	}

	// Subtest #2: Update record which needs updating

	currentUsage, err = ModifyQuotaUsage(wid, 1000)
	if err != nil {
		t.Fatalf("TestDBHandler_ModifyQuotaUsage: #2: failure to update quota: %s", err)
	}
	if currentUsage != 2000 {
		t.Fatalf("TestDBHandler_ModifyQuotaUsage: #2: bad usage value: %d", currentUsage)
	}

	// Subtest #3: Actual success

	currentUsage, err = ModifyQuotaUsage(wid, 1000)
	if err != nil {
		t.Fatalf("TestDBHandler_ModifyQuotaUsage: #3: failure to update quota: %s", err)
	}
	if currentUsage != 3000 {
		t.Fatalf("TestDBHandler_ModifyQuotaUsage: #3: bad usage value: %d", currentUsage)
	}

	// Subtest #4: Try to go lower than 0

	currentUsage, err = ModifyQuotaUsage(wid, -10000)
	if err != nil {
		t.Fatalf("TestDBHandler_ModifyQuotaUsage: #4: failure to update quota: %s", err)
	}
	if currentUsage != 0 {
		t.Fatalf("TestDBHandler_ModifyQuotaUsage: #4: bad usage value: %d", currentUsage)
	}
}

func TestDBHandler_ResetQuotaUsage(t *testing.T) {
	if err := setupTest(); err != nil {
		t.Fatalf("TestDBHandler_ResetQuotaUsage: Couldn't reset database: %s", err.Error())
	}

	resetWorkspaceDir()

	wid := "11111111-1111-1111-1111-111111111111"
	ensureTestDirectory("/ " + wid)
	makeTestFiles("/ "+wid, 5)

	row := dbConn.QueryRow(`SELECT usage FROM quotas WHERE wid=$1`, wid)

	var quotaSize int64
	err := row.Scan(&quotaSize)

	if err != sql.ErrNoRows {
		t.Fatalf("TestDBHandler_ResetQuotaUsage: Pre-execution error: %s", err)
	}

	// Subtest #1: Handle empty table

	err = ResetQuotaUsage()
	if err != nil {
		t.Fatalf("TestDBHandler_ResetQuotaUsage: #1: failure to handle empty table: %s", err)
	}

	// Subtest #2: Update existing record

	err = SetQuota(wid, 0x60_0000)
	if err != nil {
		t.Fatalf("TestDBHandler_ResetQuotaUsage: #2: failure to add quota record: %s", err)
	}

	err = ResetQuotaUsage()
	if err != nil {
		t.Fatalf("TestDBHandler_ResetQuotaUsage: #2: failure to update table: %s", err)
	}

	row = dbConn.QueryRow(`SELECT usage FROM quotas WHERE wid=$1`, wid)
	err = row.Scan(&quotaSize)
	if err != nil {
		t.Fatalf("TestDBHandler_ResetQuotaUsage: #2: failed to get quota: %s", err)
	}
	if quotaSize >= 0 {
		t.Fatal("TestDBHandler_ResetQuotaUsage: #2: quota failed to invalidate")
	}

}

func TestDBHandler_SetQuota(t *testing.T) {
	if err := setupTest(); err != nil {
		t.Fatalf("TestDBHandler_SetQuota: Couldn't reset database: %s", err.Error())
	}

	resetWorkspaceDir()

	wid := "11111111-1111-1111-1111-111111111111"
	ensureTestDirectory("/ " + wid)
	makeTestFiles("/ "+wid, 5)

	row := dbConn.QueryRow(`SELECT quota FROM quotas WHERE wid=$1`, wid)

	var quotaSize int64
	err := row.Scan(&quotaSize)

	if err != sql.ErrNoRows {
		t.Fatalf("TestDBHandler_SetQuota: Pre-execution error: %s", err)
	}

	// Subtest #1: Handle nonexistent record
	err = SetQuota(wid, 0x10_0000)
	if err != nil {
		t.Fatalf("TestDBHandler_SetQuota: #1: failure to add quota: %s", err)
	}

	row = dbConn.QueryRow(`SELECT quota FROM quotas WHERE wid=$1`, wid)
	err = row.Scan(&quotaSize)
	if err != nil {
		t.Fatalf("TestDBHandler_SetQuota: #1: failed to get quota: %s", err)
	}
	if quotaSize != 0x10_0000 {
		t.Fatalf("TestDBHandler_SetQuota: #1: got the wrong quota size: %d", quotaSize)
	}

	// Subtest #2: Update existing record
	err = SetQuota(wid, 0x60_0000)
	if err != nil {
		t.Fatalf("TestDBHandler_SetQuota: #2: failure to set quota: %s", err)
	}

	row = dbConn.QueryRow(`SELECT quota FROM quotas WHERE wid=$1`, wid)
	err = row.Scan(&quotaSize)
	if err != nil {
		t.Fatalf("TestDBHandler_SetQuota: #2: failed to get quota: %s", err)
	}
	if quotaSize != 0x60_0000 {
		t.Fatalf("TestDBHandler_SetQuota: #2: got the wrong quota size: %d", quotaSize)
	}
}

func TestDBHandler_SetQuotaUsage(t *testing.T) {
	if err := setupTest(); err != nil {
		t.Fatalf("TestDBHandler_SetQuotaUsage: Couldn't reset database: %s", err.Error())
	}

	resetWorkspaceDir()

	wid := "11111111-1111-1111-1111-111111111111"
	testPath := "/ " + wid
	ensureTestDirectory(testPath)
	generateRandomFile(testPath, 2000)

	row := dbConn.QueryRow(`SELECT usage FROM quotas WHERE wid=$1`, wid)

	var usage int64
	err := row.Scan(&usage)

	if err != sql.ErrNoRows {
		t.Fatalf("TestDBHandler_SetQuotaUsage: Pre-execution error: %s", err)
	}

	// Subtest #1: Handle nonexistent record

	err = SetQuotaUsage(wid, 1000)
	if err != nil {
		t.Fatalf("TestDBHandler_SetQuotaUsage: #1: failure to add usage: %s", err)
	}

	row = dbConn.QueryRow(`SELECT usage FROM quotas WHERE wid=$1`, wid)
	err = row.Scan(&usage)
	if err != nil {
		t.Fatalf("TestDBHandler_SetQuotaUsage: #1: failed to get usage: %s", err)
	}

	// This should be 2000 as determined by the call to generateRandomFile. If the record doesn't
	// exist, then the actual usage should be pulled from the disk
	if usage != 2000 {
		t.Fatalf("TestDBHandler_SetQuotaUsage: #1: got the wrong usage size: %d", usage)
	}

	// Subtest #2: Update existing record

	err = SetQuotaUsage(wid, 3000)
	if err != nil {
		t.Fatalf("TestDBHandler_SetQuotaUsage: #2: failure to set quota: %s", err)
	}

	row = dbConn.QueryRow(`SELECT usage FROM quotas WHERE wid=$1`, wid)
	err = row.Scan(&usage)
	if err != nil {
		t.Fatalf("TestDBHandler_SetQuotaUsage: #2: failed to get usage: %s", err)
	}
	if usage != 3000 {
		t.Fatalf("TestDBHandler_SetQuotaUsage: #2: got the wrong usage size: %d", usage)
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
// PreregWorkspace
// RemoveDevice
// RemoveExpiredPasscodes
// RemoveWorkspace
// ResetPassword
// ResetQuotaUsage
// ResolveAddress
// SetPassword
// SetWorkspaceStatus
// UpdateDevice
