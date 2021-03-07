package fshandler

import (
	"errors"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/darkwyrm/mensagod/config"
	"github.com/google/uuid"
	"github.com/spf13/viper"
)

// setupTest initializes the global config and resets the workspace directory
func setupTest() error {

	// In this case we don't care about the diceware wordlist returned. Note that
	// resetWorkspaceDir depends on initialization of the server config, so this call must go
	// first
	config.SetupConfig()

	err := resetWorkspaceDir()
	if err != nil {
		return err
	}

	return nil
}

// resetWorkspaceDir empties out the workspace directory to make sure it's ready for a filesystem
// test. Because the workspace directory may have special permissions set on it, we can't just
// delete the directory and recreate it--we have to actually empty the directory.
func resetWorkspaceDir() error {
	var anpath LocalAnPath
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

	var anpath LocalAnPath
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
	filename := GenerateFileName(size)

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

	var anpath LocalAnPath
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
		_, err = generateRandomFile(anpath.MensagoPath(), filesize)
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

	var anpath LocalAnPath
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
// an Mensago-format path, resulting in a path relative to the workspace root.
func ensureTestDirectory(path string) error {
	var anpath LocalAnPath
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

func TestLocalFSHandler_CopyFile(t *testing.T) {
	err := setupTest()
	if err != nil {
		t.Fatalf("TestLocalFSHandler_CopyFile: Couldn't reset workspace dir: %s",
			err.Error())
	}

	wid := "11111111-1111-1111-1111-111111111111"
	srcDirName := "10000000-0000-0000-0000-000000000001"
	destDirName := "20000000-0000-0000-0000-000000000002"
	fsh := GetFSProvider()

	err = fsh.MakeDirectory("/ " + wid + " " + srcDirName)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_CopyFile: Couldn't create source directory: %s",
			err.Error())
	}
	err = fsh.MakeDirectory("/ " + wid + " " + destDirName)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_CopyFile: Couldn't create destination directory: %s",
			err.Error())
	}

	// Subtest #1: Bad path

	sourcePath := strings.Join([]string{"/", wid, "12345678-1234-1234-1234-1234567890ab",
		GenerateFileName(1000)}, " ")
	_, err = fsh.CopyFile(sourcePath, sourcePath)
	if err == nil {
		t.Fatalf("TestLocalFSHandler_CopyFile: subtest #1 failed to handle bad path")
	}

	// Subtest #2: Missing source file

	sourcePath = strings.Join([]string{"/", wid, srcDirName, GenerateFileName(1000)}, " ")
	_, err = fsh.CopyFile(sourcePath, sourcePath)
	if err == nil {
		t.Fatalf("TestLocalFSHandler_CopyFile: subtest #2 failed to handle missing file")
	}

	// Subtest #3: Missing destination

	tempHandle, tempName, err := fsh.MakeTempFile(wid)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_CopyFile: unexpected error making temp file for subtest #3: %s",
			err.Error())
	}
	tempHandle.Close()

	tempName, err = fsh.InstallTempFile(wid, tempName,
		strings.Join([]string{"/", wid, srcDirName}, " "))

	sourcePath = strings.Join([]string{"/", wid, srcDirName, tempName}, " ")
	destPath := strings.Join([]string{"/", wid, "12345678-1234-1234-1234-1234567890ab"}, " ")
	_, err = fsh.CopyFile(sourcePath, destPath)
	if err == nil {
		t.Fatalf("TestLocalFSHandler_CopyFile: subtest #3 failed to handle missing destination")
	}

	// Subtest #4: Actual success

	destPath = strings.Join([]string{"/", wid, destDirName}, " ")
	_, err = fsh.CopyFile(sourcePath, destPath)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_CopyFile: subtest #4 failed to move file: %s",
			err.Error())
	}
}

func TestLocalFSHandler_CloseFile(t *testing.T) {
	err := setupTest()
	if err != nil {
		t.Fatalf("TestLocalFSHandler_CloseFile: Couldn't reset workspace dir: %s",
			err.Error())
	}

	wid := "11111111-1111-1111-1111-111111111111"
	fsh := GetFSProvider()

	// Subtest #1: File not open

	filePath := strings.Join([]string{"/", wid, "12345678-1234-1234-1234-1234567890ab",
		GenerateFileName(1000)}, " ")
	_, err = fsh.OpenFile(filePath)
	if err == nil {
		t.Fatalf("TestLocalFSHandler_CloseFile: subtest #1 failed to handle missing handle")
	}

	// Subtest #2: Actual success

	fsh.MakeDirectory("/ " + wid)
	tempName, err := generateRandomFile("/ "+wid, 10240)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_CloseFile: subtest #2 failed to create temp file: %s",
			err.Error())
	}

	filePath = strings.Join([]string{"/", wid, tempName}, " ")
	handle, err := fsh.OpenFile(filePath)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_CloseFile: subtest #2 failed to open file: %s",
			err.Error())
	}

	err = fsh.CloseFile(handle)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_CloseFile: subtest #2 failed to close file: %s",
			err.Error())
	}

	_, exists := fsh.Files[handle]
	if exists {
		t.Fatal("TestLocalFSHandler_CloseFile: subtest #2 handle still exists after close")
	}
}

func TestLocalFSHandler_DeleteFile(t *testing.T) {
	err := setupTest()
	if err != nil {
		t.Fatalf("TestLocalFSHandler_DeleteFile: Couldn't reset workspace dir: %s",
			err.Error())
	}

	wid := "11111111-1111-1111-1111-111111111111"
	fsh := GetFSProvider()

	// Subtest #1: Bad path

	filePath := strings.Join([]string{"/", wid, "12345678-1234-1234-1234-1234567890ab",
		GenerateFileName(1000)}, " ")
	err = fsh.DeleteFile(filePath)
	if err == nil {
		t.Fatalf("TestLocalFSHandler_DeleteFile: subtest #1 failed to handle bad path")
	}

	// Subtest #2: File doesn't exist

	filePath = strings.Join([]string{"/", wid, GenerateFileName(1000)}, " ")
	err = fsh.DeleteFile(filePath)
	if err == nil {
		t.Fatalf("TestLocalFSHandler_DeleteFile: subtest #2 failed to handle nonexistent file")
	}

	// Subtest #3: Actual success

	tempHandle, tempName, err := fsh.MakeTempFile(wid)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_DeleteFile: unexpected error making temp file for "+
			"subtest #3: %s", err.Error())
	}
	tempHandle.Close()

	fsh.MakeDirectory("/ " + wid)
	tempName, err = fsh.InstallTempFile(wid, tempName, "/ "+wid)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_DeleteFile: subtest #3 failed to install temp file: %s",
			err.Error())
	}

	filePath = strings.Join([]string{"/", wid, tempName}, " ")
	err = fsh.DeleteFile(filePath)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_DeleteFile: subtest #3 failed to delete file: %s",
			err.Error())
	}
}

func TestLocalFSHandler_Exists(t *testing.T) {
	err := setupTest()
	if err != nil {
		t.Fatalf("TestLocalFSHandler_Exists: Couldn't reset workspace dir: %s", err.Error())
	}

	wid := "11111111-1111-1111-1111-111111111111"
	testFile := "1613915806.1251.850ff5d0-a191-4f4e-8104-a71db98296a3"
	testPath := strings.Join([]string{"/", wid, testFile}, " ")

	err = ensureTestDirectory("/ " + wid)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_Exists: Couldn't create wid: %s", err.Error())
	}

	fsh := GetFSProvider()

	// Subtest #1: bad path
	_, err = fsh.Exists("/var/mensago/" + wid)
	if err == nil {
		t.Fatal("TestLocalFSHandler_Exists: failed to handle bad path")
	}

	// Subtest #2: nonexistent file
	exists, err := fsh.Exists(testPath)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_Exists: subtest #2 unexpected error: %s", err.Error())
	}
	if exists {
		t.Fatal("TestLocalFSHandler_Exists: failed to handle nonexistent file")
	}

	// Subtest #3: actual file -- success
	testFile, err = generateRandomFile("/ "+wid, 1024)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_Exists: subtest #3 unexpected error: %s", err.Error())
	}

	testPath = strings.Join([]string{"/", wid, testFile}, " ")
	exists, err = fsh.Exists(testPath)
	if !exists {
		t.Fatal("TestLocalFSHandler_Exists: failed to handle file existence")
	}
}

func TestLocalFSHandler_GetDiskUsage(t *testing.T) {
	err := setupTest()
	if err != nil {
		t.Fatalf("TestLocalFSHandler_GetDiskUsage: Couldn't reset workspace dir: %s", err.Error())
	}

	wid := "11111111-1111-1111-1111-111111111111"
	testPath := "/ " + wid
	fsh := GetFSProvider()

	// Subtest #1: bad WID

	_, err = fsh.GetDiskUsage("11111111-1111-1111-1111")
	if err == nil {
		t.Fatal("TestLocalFSHandler_ListFiles: #1: failed to handle bad WID")
	}

	// Subtest #2: non-existent WID

	_, err = fsh.GetDiskUsage("/ 22222222-2222-2222-2222-222222222222")
	if err == nil {
		t.Fatal("TestLocalFSHandler_ListFiles: #2: failed to handle missing workspace directory")
	}

	// Subtest #3: Single directory of files

	err = ensureTestDirectory(testPath)
	if err != nil {
		t.Fatal("TestLocalFSHandler_ListFiles: #3: failed to create workspace directory")
	}

	for _, testSize := range []int{1000, 2000, 3000, 4000} {
		_, err = generateRandomFile(testPath, testSize)
		if err != nil {
			t.Fatal("TestLocalFSHandler_ListFiles: #3: failed to create test files")
		}
	}
	fileSize, err := fsh.GetDiskUsage(wid)
	if err != nil {
		t.Fatal("TestLocalFSHandler_ListFiles: #3: failed to get disk usage")
	}
	if fileSize != 10_000 {
		t.Fatalf("TestLocalFSHandler_ListFiles: #3: got wrong file size: %d", fileSize)
	}
}

func TestLocalFSHandler_InstallTempFile(t *testing.T) {
	err := setupTest()
	if err != nil {
		t.Fatalf("TestLocalFSHandler_InstallTempFile: Couldn't reset workspace dir: %s",
			err.Error())
	}

	wid := "11111111-1111-1111-1111-111111111111"
	fsh := GetFSProvider()

	// Subtest #2: destination doesn't exist

	handle, name, err := fsh.MakeTempFile(wid)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_InstallTempFile: subtest #1 unexpected error making "+
			"temp file : %s", err.Error())
	}

	_, err = handle.Write([]byte("This is some text"))
	if err != nil {
		t.Fatalf("TestLocalFSHandler_InstallTempFile: subtest #1 unexpected error writing "+
			"to temp file : %s", err.Error())
	}
	handle.Close()

	destPath := "/ " + wid

	_, err = fsh.InstallTempFile(wid, name, destPath)
	if err == nil {
		t.Fatal("TestLocalFSHandler_InstallTempFile: subtest #2 failed to handle missing " +
			"destination")
	}

	// Subtest #3: actual success
	err = fsh.MakeDirectory(destPath)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_InstallTempFile: subtest #3 unexpected error creating "+
			"destination directory : %s", err.Error())
	}
	newName, err := fsh.InstallTempFile(wid, name, destPath)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_InstallTempFile: subtest #3 unexpected error installing "+
			"temp file : %s", err.Error())
	}

	if !ValidateFileName(newName) {
		t.Fatal("TestLocalFSHandler_InstallTempFile: subtest #3 bad format for temp file new name")
	}
}

func TestLocalFSHandler_ListFiles(t *testing.T) {
	err := setupTest()
	if err != nil {
		t.Fatalf("TestLocalFSHandler_ListFiles: Couldn't reset workspace dir: %s", err.Error())
	}

	wid := "11111111-1111-1111-1111-111111111111"
	testPath := "/ " + wid
	fsh := GetFSProvider()

	// Subtest #1: bad path

	err = fsh.MakeDirectory("/var/mensago/" + wid)
	if err == nil {
		t.Fatal("TestLocalFSHandler_ListFiles: failed to handle bad path")
	}

	// Subtest #2: directory doesn't exist

	_, err = fsh.ListFiles(testPath, 0)
	if err == nil {
		t.Fatalf("TestLocalFSHandler_ListFiles: subtest #2 failed to handle nonexistent dir: %s",
			err.Error())
	}

	// Subtest #3: empty directory

	err = fsh.MakeDirectory("/ " + wid)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_ListFiles: subtest #3 failed to create test dir: %s",
			err.Error())
	}
	testFiles, err := fsh.ListFiles(testPath, 0)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_ListFiles: subtest #3 unexpected error: %s",
			err.Error())
	}
	if len(testFiles) > 0 {
		t.Fatal("TestLocalFSHandler_ListFiles: subtest #3 failed to handle empty directory")
	}

	// Subtest #4: actual success

	err = makeTestFiles(testPath, 3)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_ListFiles: subtest #4 unexpected error making test files: %s",
			err.Error())
	}
	testFiles, err = fsh.ListFiles(testPath, 0)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_ListFiles: subtest #4 unexpected error listing files: %s",
			err.Error())
	}
	if len(testFiles) != 3 {
		t.Fatal("TestLocalFSHandler_ListFiles: subtest #4 bad file count")
	}

	// Subtest #5: path is a file

	_, err = fsh.ListFiles(testPath+" "+testFiles[0], 0)
	if err == nil {
		t.Fatalf("TestLocalFSHandler_ListFiles: subtest #5 failed to handle path to file: %s",
			err.Error())
	}

	// Subtest #6: filtered file listing
	time.Sleep(time.Second)
	timeFilter := time.Now().Unix()
	err = makeTestFiles(testPath, 2)

	testFiles, err = fsh.ListFiles(testPath, timeFilter)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_ListFiles: subtest #6 unexpected error listing files: %s",
			err.Error())
	}
	if len(testFiles) != 2 {
		t.Fatal("TestLocalFSHandler_ListFiles: subtest #6 bad filtered file count")
	}
}

func TestLocalFSHandler_ListDirectories(t *testing.T) {
	err := setupTest()
	if err != nil {
		t.Fatalf("TestLocalFSHandler_ListDirectories: Couldn't reset workspace dir: %s",
			err.Error())
	}

	wid := "11111111-1111-1111-1111-111111111111"
	subwids := []string{
		"22222222-2222-2222-2222-222222222222",
		"33333333-3333-3333-3333-333333333333",
		"44444444-4444-4444-4444-444444444444"}
	testPath := "/ " + wid
	fsh := GetFSProvider()

	// Subtest #1: bad path

	err = fsh.MakeDirectory("/var/mensago/" + wid)
	if err == nil {
		t.Fatal("TestLocalFSHandler_ListDirectories: failed to handle bad path")
	}

	// Subtest #2: directory doesn't exist

	_, err = fsh.ListDirectories(testPath)
	if err == nil {
		t.Fatalf("TestLocalFSHandler_ListDirectories: subtest #2 failed to handle "+
			"nonexistent dir: %s", err.Error())
	}

	// Subtest #3: empty directory

	err = fsh.MakeDirectory("/ " + wid)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_ListDirectories: subtest #3 failed to create test dir: %s",
			err.Error())
	}
	testFiles, err := fsh.ListDirectories(testPath)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_ListDirectories: subtest #3 unexpected error: %s",
			err.Error())
	}
	if len(testFiles) > 0 {
		t.Fatal("TestLocalFSHandler_ListDirectories: subtest #3 failed to handle empty directory")
	}

	// Subtest #4: directory has no subdirectories

	err = makeTestFiles(testPath, 3)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_ListDirectories: subtest #4 unexpected error making "+
			"test files: %s", err.Error())
	}
	testFiles, err = fsh.ListDirectories(testPath)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_ListDirectories: subtest #4 unexpected error listing "+
			"files: %s", err.Error())
	}
	if len(testFiles) != 0 {
		t.Fatal("TestLocalFSHandler_ListDirectories: subtest #4 bad directory count")
	}

	// Subtest #5: actual success
	for _, subwid := range subwids {
		subwidPath := strings.Join([]string{"/", wid, subwid}, " ")
		err = fsh.MakeDirectory(subwidPath)
		if err != nil {
			t.Fatalf("TestLocalFSHandler_ListDirectories: subtest #5 unexpected error making "+
				"test directory %s: %s", subwid, err.Error())
		}
	}
	testFiles, err = fsh.ListDirectories(testPath)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_ListDirectories: subtest #5 unexpected error listing "+
			"files: %s", err.Error())
	}
	if len(testFiles) != len(subwids) {
		t.Fatal("TestLocalFSHandler_ListDirectories: subtest #5 bad directory count")
	}
}

func TestLocalFSHandler_MakeDirectory(t *testing.T) {
	err := setupTest()
	if err != nil {
		t.Fatalf("TestLocalFSHandler_MakeDirectory: Couldn't reset workspace dir: %s", err.Error())
	}

	wid := "11111111-1111-1111-1111-111111111111"
	wid2 := "22222222-2222-2222-2222-222222222222"
	fsh := GetFSProvider()

	// Subtest #1: bad path
	err = fsh.MakeDirectory("/var/mensago/" + wid)
	if err == nil {
		t.Fatal("TestLocalFSHandler_MakeDirectory: failed to handle bad path")
	}

	// Subtest #2: actual success
	err = fsh.MakeDirectory("/ " + wid)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_MakeDirectory: subtest #2 failed to create dir: %s",
			err.Error())
	}

	// Subtest #3: directory already exists
	err = fsh.MakeDirectory("/ " + wid)
	if err == nil {
		t.Fatalf("TestLocalFSHandler_MakeDirectory: subtest #3 failed to handle existing dir: %s",
			err.Error())
	}

	// Subtest #4: recursive creation

	testDir := strings.Join([]string{"/", wid, wid2}, " ")
	err = fsh.MakeDirectory(testDir)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_MakeDirectory: subtest #4 failed to recursive create dir: %s",
			err.Error())
	}
}

func TestLocalFSHandler_MakeTempFile(t *testing.T) {
	err := setupTest()
	if err != nil {
		t.Fatalf("TestLocalFSHandler_MakeTempFile: Couldn't reset workspace dir: %s",
			err.Error())
	}

	wid := "11111111-1111-1111-1111-111111111111"
	fsh := GetFSProvider()

	// Subtest #1: bad WID

	_, _, err = fsh.MakeTempFile("not a wid")
	if err == nil {
		t.Fatal("TestLocalFSHandler_MakeTempFile: failed to handle bad wid")
	}

	// Subtest #2: actual success

	handle, name, err := fsh.MakeTempFile(wid)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_MakeTempFile: unexpected error making temp file : %s",
			err.Error())
	}
	defer handle.Close()

	pattern := regexp.MustCompile(
		"^[0-9]+\\." +
			"[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$")
	if !pattern.MatchString(name) {
		t.Fatal("TestLocalFSHandler_MakeTempFile: bad temp file name format")
	}
	if handle == nil {
		t.Fatal("TestLocalFSHandler_MakeTempFile: null temp file handle")
	}

	_, err = handle.Write([]byte("This is some text"))
	if err != nil {
		t.Fatalf("TestLocalFSHandler_MakeTempFile: unexpected error writing to temp file : %s",
			err.Error())
	}

	expectedPath := filepath.Join(viper.GetString("global.workspace_dir"), "tmp", wid, name)
	_, err = os.Stat(expectedPath)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_MakeTempFile: failed to stat temp file: %s",
			err.Error())
	}
}

func TestLocalFSHandler_MoveFile(t *testing.T) {
	err := setupTest()
	if err != nil {
		t.Fatalf("TestLocalFSHandler_MoveFile: Couldn't reset workspace dir: %s",
			err.Error())
	}

	wid := "11111111-1111-1111-1111-111111111111"
	srcDirName := "10000000-0000-0000-0000-000000000001"
	destDirName := "20000000-0000-0000-0000-000000000002"
	fsh := GetFSProvider()

	err = fsh.MakeDirectory("/ " + wid + " " + srcDirName)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_MoveFile: Couldn't create source directory: %s",
			err.Error())
	}
	err = fsh.MakeDirectory("/ " + wid + " " + destDirName)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_MoveFile: Couldn't create destination directory: %s",
			err.Error())
	}

	// Subtest #1: Bad path

	sourcePath := strings.Join([]string{"/", wid, "12345678-1234-1234-1234-1234567890ab",
		GenerateFileName(1000)}, " ")
	err = fsh.MoveFile(sourcePath, sourcePath)
	if err == nil {
		t.Fatalf("TestLocalFSHandler_MoveFile: subtest #1 failed to handle bad path")
	}

	// Subtest #2: Missing source file

	sourcePath = strings.Join([]string{"/", wid, srcDirName, GenerateFileName(1000)}, " ")
	err = fsh.MoveFile(sourcePath, sourcePath)
	if err == nil {
		t.Fatalf("TestLocalFSHandler_MoveFile: subtest #2 failed to handle missing file")
	}

	// Subtest #3: Missing destination

	tempHandle, tempName, err := fsh.MakeTempFile(wid)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_MoveFile: unexpected error making temp file for subtest #3: %s",
			err.Error())
	}
	tempHandle.Close()

	tempName, err = fsh.InstallTempFile(wid, tempName,
		strings.Join([]string{"/", wid, srcDirName}, " "))

	sourcePath = strings.Join([]string{"/", wid, srcDirName, tempName}, " ")
	destPath := strings.Join([]string{"/", wid, "12345678-1234-1234-1234-1234567890ab"}, " ")
	err = fsh.MoveFile(sourcePath, destPath)
	if err == nil {
		t.Fatalf("TestLocalFSHandler_MoveFile: subtest #3 failed to handle missing destination")
	}

	// Subtest #4: Actual success

	destPath = strings.Join([]string{"/", wid, destDirName}, " ")
	err = fsh.MoveFile(sourcePath, destPath)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_MoveFile: subtest #4 failed to move file: %s",
			err.Error())
	}

	// Subtest #5: File exists in destination

	existingName := tempName
	tempHandle, tempName, err = fsh.MakeTempFile(wid)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_MoveFile: unexpected error making temp file for subtest #3: %s",
			err.Error())
	}
	tempHandle.Close()

	// Rename the new temp file to match exactly to the name of the file from the previous subtest
	topDir := viper.GetString("global.workspace_dir")
	err = os.Rename(filepath.Join(topDir, "tmp", wid, tempName),
		filepath.Join(topDir, "tmp", wid, existingName))

	tempName, err = fsh.InstallTempFile(wid, existingName,
		strings.Join([]string{"/", wid, srcDirName}, " "))

	sourcePath = strings.Join([]string{"/", wid, srcDirName, existingName}, " ")
	destPath = strings.Join([]string{"/", wid, destDirName}, " ")
	err = fsh.MoveFile(sourcePath, destPath)
	if err == nil {
		t.Fatalf("TestLocalFSHandler_MoveFile: subtest #5 failed to handle existing file " +
			"in destination")
	}
}

func TestLocalFSHandler_OpenReadFile(t *testing.T) {
	err := setupTest()
	if err != nil {
		t.Fatalf("TestLocalFSHandler_OpenReadFile: Couldn't reset workspace dir: %s",
			err.Error())
	}

	wid := "11111111-1111-1111-1111-111111111111"
	fsh := GetFSProvider()

	// Subtest #1: Bad path

	filePath := strings.Join([]string{"/", wid, "12345678-1234-1234-1234-1234567890ab",
		GenerateFileName(1000)}, " ")
	_, err = fsh.OpenFile(filePath)
	if err == nil {
		t.Fatalf("TestLocalFSHandler_OpenReadFile: subtest #1 failed to handle bad path")
	}

	// Subtest #2: File doesn't exist

	filePath = strings.Join([]string{"/", wid, GenerateFileName(1000)}, " ")
	_, err = fsh.OpenFile(filePath)
	if err == nil {
		t.Fatalf("TestLocalFSHandler_OpenReadFile: subtest #2 failed to handle nonexistent file")
	}

	// Subtest #3: Actual success and read to EOF

	fsh.MakeDirectory("/ " + wid)
	tempName, err := generateRandomFile("/ "+wid, 10240)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_OpenReadFile: subtest #3 failed to create temp file: %s",
			err.Error())
	}

	filePath = strings.Join([]string{"/", wid, tempName}, " ")
	handle, err := fsh.OpenFile(filePath)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_OpenReadFile: subtest #3 failed to open file: %s",
			err.Error())
	}

	buffer := make([]byte, 1000)
	bytesRead, err := fsh.ReadFile(handle, buffer)
	if bytesRead != 1000 || err != nil {
		t.Fatalf("TestLocalFSHandler_OpenReadFile: subtest #3 first read failed: %v bytes read",
			bytesRead)
	}
	for bytesRead > 0 {
		bytesRead, err = fsh.ReadFile(handle, buffer)
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("TestLocalFSHandler_OpenReadFile: subtest #3 loop read failed: %v bytes read",
				bytesRead)
		}
	}
	_, exists := fsh.Files[handle]
	if exists {
		t.Fatal("TestLocalFSHandler_OpenReadFile: subtest #3 handle still exists after close")
	}
}

func TestLocalFSHandler_RemoveDirectory(t *testing.T) {
	err := setupTest()
	if err != nil {
		t.Fatalf("TestLocalFSHandler_RemoveDirectory: Couldn't reset workspace dir: %s", err.Error())
	}

	wid := "11111111-1111-1111-1111-111111111111"
	wid2 := "22222222-2222-2222-2222-222222222222"
	fsh := GetFSProvider()

	// Subtest #1: bad path

	err = fsh.MakeDirectory("/var/mensago/" + wid)
	if err == nil {
		t.Fatal("TestLocalFSHandler_RemoveDirectory: failed to handle bad path")
	}

	// Subtest #2: directory doesn't exist

	err = fsh.RemoveDirectory("/ "+wid, false)
	if err == nil {
		t.Fatalf("TestLocalFSHandler_RemoveDirectory: subtest #2 failed to handle nonexistent dir: %s",
			err.Error())
	}

	// Subtest #3: actual success

	err = fsh.MakeDirectory("/ " + wid)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_RemoveDirectory: subtest #3 failed to create dir: %s",
			err.Error())
	}
	err = fsh.RemoveDirectory("/ "+wid, false)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_RemoveDirectory: subtest #3 failed to remove dir: %s",
			err.Error())
	}

	// Subtest #4: recursive removal

	testDir := strings.Join([]string{"/", wid, wid2}, " ")
	err = fsh.MakeDirectory(testDir)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_RemoveDirectory: subtest #4 failed to create dir: %s",
			err.Error())
	}
	err = makeTestFiles(testDir, 1)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_RemoveDirectory: subtest #4 failed to test files: %s",
			err.Error())
	}
	err = fsh.RemoveDirectory(testDir, true)
	if err != nil {
		t.Fatalf("TestLocalFSHandler_RemoveDirectory: subtest #4 failed to remove dir: %s",
			err.Error())
	}
}
