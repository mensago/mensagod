package fshandler

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/darkwyrm/mensagod/logging"
	"github.com/spf13/viper"
)

// LocalFSHandler represents local storage on the server
type LocalFSHandler struct {
	BasePath      string
	PathSeparator string
	Files         map[string]LocalFSHandle
}

var providerLock = &sync.Mutex{}
var localProviderInstance *LocalFSHandler

// LocalFSHandle represents an open file and provides Open(), Read(), and Close() methods
type LocalFSHandle struct {
	Path   string
	Handle *os.File
}

// GetFSHandler returns a new filesystem provider which interacts with the local filesystem.
// It obtains the necessary information about the local filesystem directly from the server
// configuration data.
func GetFSHandler() *LocalFSHandler {
	if localProviderInstance == nil {
		providerLock.Lock()
		defer providerLock.Unlock()

		if localProviderInstance == nil {
			var provider LocalFSHandler

			provider.BasePath = viper.GetString("global.workspace_dir")

			switch runtime.GOOS {
			case "windows":
				provider.PathSeparator = "\\"
			default:
				provider.PathSeparator = "/"
			}

			provider.Files = make(map[string]LocalFSHandle, 100)
			localProviderInstance = &provider
		}
	}

	return localProviderInstance
}

// CopyFile creates a duplicate of the specified source file in the specified destination folder
// and returns the name of the new file
func (lfs *LocalFSHandler) CopyFile(source string, dest string) (string, error) {
	// Path validation handled in FromPath()
	var srcAnpath LocalAnPath
	err := srcAnpath.Set(source)
	if err != nil {
		return "", err
	}

	stat, err := os.Stat(srcAnpath.ProviderPath())
	if err != nil {
		return "", err
	}
	if !stat.Mode().IsRegular() {
		return "", errors.New("source path is a not file")
	}
	if !ValidateFileName(filepath.Base(srcAnpath.ProviderPath())) {
		return "", errors.New("bad filename format")
	}

	// Path validation handled in FromPath()
	var destAnpath LocalAnPath
	err = destAnpath.Set(dest)
	if err != nil {
		return "", err
	}

	stat, err = os.Stat(destAnpath.ProviderPath())
	if err != nil {
		return "", err
	}
	if !stat.IsDir() {
		return "", errors.New("destination path is not a directory")
	}

	parts := strings.Split(filepath.Base(srcAnpath.ProviderPath()), ".")
	filesize, _ := strconv.Atoi(parts[1])
	newName := GenerateFileName(filesize)
	newPath := filepath.Join(destAnpath.ProviderPath(), newName)
	_, err = os.Stat(newPath)
	if err == nil {
		return "", errors.New("source exists in destination path")
	}

	sourceHandle, err := os.Open(srcAnpath.ProviderPath())
	if err != nil {
		return "", err
	}
	defer sourceHandle.Close()

	destHandle, err := os.Create(newPath)
	if err != nil {
		return "", err
	}
	defer destHandle.Close()

	_, err = io.Copy(destHandle, sourceHandle)
	return newName, err
}

// CloseFile closes the specified file handle. It is not normally needed unless Read() returns an
// error or the caller must abort reading the file.
func (lfs *LocalFSHandler) CloseFile(handle string) error {
	lfsh, exists := lfs.Files[handle]
	if !exists {
		return os.ErrNotExist
	}
	lfsh.Handle.Close()
	delete(lfs.Files, handle)
	return nil
}

// DeleteFile deletes the specified workspace file. If the file does not exist, this function will
// not return an error.
func (lfs *LocalFSHandler) DeleteFile(path string) error {
	// Path validation handled in Set()
	var anpath LocalAnPath
	err := anpath.Set(path)
	if err != nil {
		return err
	}

	_, err = os.Stat(anpath.ProviderPath())
	if err != nil {
		return err
	}

	return os.Remove(anpath.ProviderPath())
}

// Exists checks to see if the specified path exists
func (lfs *LocalFSHandler) Exists(path string) (bool, error) {

	// Path validation handled in Set()
	var anpath LocalAnPath
	err := anpath.Set(path)
	if err != nil {
		return false, err
	}

	_, err = os.Stat(anpath.ProviderPath())
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

// GetDiskUsage calculates the disk usage of a workspace
func (lfs *LocalFSHandler) GetDiskUsage(wid string) (uint64, error) {
	// Path validation handled in Set()
	var anpath LocalAnPath
	err := anpath.Set("/ " + wid)
	if err != nil {
		return 0, err
	}

	var totalSize uint64
	err = filepath.WalkDir(anpath.ProviderPath(), func(_ string, info fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || !ValidateFileName(info.Name()) {
			return nil
		}
		parts := strings.Split(info.Name(), ".")
		fileSize, _ := strconv.ParseInt(parts[1], 10, 64)
		totalSize += uint64(fileSize)

		return err
	})
	return totalSize, err
}

// InstallTempFile moves a file from the temporary file area to its location in a workspace
func (lfs *LocalFSHandler) InstallTempFile(wid string, name string, dest string) (string, error) {
	pattern := regexp.MustCompile("[\\da-fA-F]{8}-?[\\da-fA-F]{4}-?[\\da-fA-F]{4}-?[\\da-fA-F]{4}-?[\\da-fA-F]{12}")
	if (len(wid) != 36 && len(wid) != 32) || !pattern.MatchString(wid) {
		return "", errors.New("bad workspace id")
	}

	pattern = regexp.MustCompile(
		"^[0-9]+\\." +
			"[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$")
	if !pattern.MatchString(name) {
		return "", errors.New("bad tempfile name")
	}

	srcpath := filepath.Join(viper.GetString("global.workspace_dir"), "tmp", wid, name)

	var destAnpath LocalAnPath
	err := destAnpath.Set(dest)
	if err != nil {
		return "", err
	}

	stat, err := os.Stat(srcpath)
	if err != nil {
		return "", err
	}
	if !stat.Mode().IsRegular() {
		return "", errors.New("source path is a not file")
	}
	filesize := stat.Size()

	stat, err = os.Stat(destAnpath.ProviderPath())
	if err != nil {
		return "", err
	}
	if !stat.Mode().IsDir() {
		return "", errors.New("destination path is a not directory")
	}

	parts := strings.Split(name, ".")
	newname := fmt.Sprintf("%s.%d.%s", parts[0], filesize, parts[1])

	err = os.Rename(srcpath, filepath.Join(destAnpath.ProviderPath(), newname))
	if err != nil {
		return "", err
	}

	return newname, nil
}

// ListDirectories returns the names of all subdirectories of the specified path
func (lfs *LocalFSHandler) ListDirectories(path string) ([]string, error) {
	// Path validation handled in FromPath()
	var anpath LocalAnPath
	err := anpath.Set(path)
	if err != nil {
		return nil, err
	}

	stat, err := os.Stat(anpath.ProviderPath())
	if err != nil {
		return nil, err
	}
	if !stat.IsDir() {
		return nil, errors.New("directory path is a file")
	}

	handle, err := os.Open(anpath.ProviderPath())
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	list, _ := handle.Readdirnames(0)

	pattern := regexp.MustCompile(
		"^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$")

	out := make([]string, 0, len(list))
	for _, name := range list {
		if pattern.MatchString(name) {
			stat, err = os.Stat(anpath.ProviderPath())
			if err != nil {
				return nil, err
			}
			if stat.IsDir() {
				out = append(out, name)
			}
		}
	}
	return out, nil
}

// ListFiles returns all files in the specified path after the specified time. Note that the time
// is in UNIX time, i.e. seconds since the epoch. To return all files, pass a 0.
func (lfs *LocalFSHandler) ListFiles(path string, afterTime int64) ([]string, error) {
	// Path validation handled in FromPath()
	var anpath LocalAnPath
	err := anpath.Set(path)
	if err != nil {
		return nil, err
	}

	stat, err := os.Stat(anpath.ProviderPath())
	if err != nil {
		return nil, err
	}
	if !stat.IsDir() {
		return nil, errors.New("directory path is a file")
	}

	handle, err := os.Open(anpath.ProviderPath())
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	list, _ := handle.Readdirnames(0)

	pattern := regexp.MustCompile(
		"^[0-9]+\\.[0-9]+\\.[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$")

	out := make([]string, 0, len(list))
	for _, name := range list {
		if pattern.MatchString(name) {
			if afterTime > 0 {
				parts := strings.Split(name, ".")
				filetime, err := strconv.ParseInt(parts[0], 10, 64)
				if err != nil || afterTime > filetime {
					continue
				}
			}
			out = append(out, name)
		}
	}
	return out, nil
}

// MakeDirectory creates a directory in the local filesystem relative to the workspace folder
func (lfs *LocalFSHandler) MakeDirectory(path string) error {

	// Path validation handled in FromPath()
	var anpath LocalAnPath
	err := anpath.Set(path)
	if err != nil {
		return err
	}

	_, err = os.Stat(anpath.LocalPath)
	if err == nil {
		return os.ErrExist
	}

	return os.MkdirAll(anpath.LocalPath, 0770)
}

// MakeTempFile creates a file in the temporary file area and returns a handle to it. The caller is
// responsible for closing the handle when finished.
func (lfs *LocalFSHandler) MakeTempFile(wid string) (*os.File, string, error) {

	pattern := regexp.MustCompile("[\\da-fA-F]{8}-?[\\da-fA-F]{4}-?[\\da-fA-F]{4}-?[\\da-fA-F]{4}-?[\\da-fA-F]{12}")
	if (len(wid) != 36 && len(wid) != 32) || !pattern.MatchString(wid) {
		return nil, "", errors.New("bad workspace id")
	}

	tempDirPath := filepath.Join(viper.GetString("global.workspace_dir"), "tmp", wid)

	stat, err := os.Stat(tempDirPath)
	if err != nil {
		if os.IsNotExist(err) {
			err = os.MkdirAll(tempDirPath, 0600)
			if err != nil {
				return nil, "", err
			}
		} else {
			return nil, "", err
		}
	} else {
		if !stat.Mode().IsDir() {
			return nil, "", errors.New("destination path is a not directory")
		}
	}

	tempFileName := ""
	tempFilePath := ""
	for tempFileName == "" {
		proposedName := GenerateTempFileName()

		tempFilePath = filepath.Join(tempDirPath, proposedName)
		_, err := os.Stat(tempFilePath)
		if err != nil {
			tempFileName = proposedName
			break
		}
	}

	handle, err := os.Create(tempFilePath)
	if err != nil {
		logging.Writef("Couldn't save temp file %s: %s", tempFilePath, err.Error())
		return nil, "", err
	}

	return handle, tempFileName, nil
}

// MoveFile moves the specified file to the specified directory. Note that dest MUST point to
// a directory.
func (lfs *LocalFSHandler) MoveFile(source string, dest string) error {
	// Path validation handled in FromPath()
	var srcAnpath LocalAnPath
	err := srcAnpath.Set(source)
	if err != nil {
		return err
	}

	stat, err := os.Stat(srcAnpath.ProviderPath())
	if err != nil {
		return err
	}
	if !stat.Mode().IsRegular() {
		return errors.New("source path is a not file")
	}

	// Path validation handled in FromPath()
	var destAnpath LocalAnPath
	err = destAnpath.Set(dest)
	if err != nil {
		return err
	}

	stat, err = os.Stat(destAnpath.ProviderPath())
	if err != nil {
		return err
	}
	if !stat.IsDir() {
		return errors.New("destination path is not a directory")
	}

	newPath := filepath.Join(destAnpath.ProviderPath(), filepath.Base(srcAnpath.ProviderPath()))
	fmt.Println(newPath)
	_, err = os.Stat(newPath)
	if err == nil {
		return errors.New("source exists in destination path")
	}

	return os.Rename(srcAnpath.ProviderPath(), newPath)
}

// OpenFile opens the specified file for reading data and returns a file handle as a string. The
// contents of the handle are specific to the provider and should not be expected to follow any
// particular format
func (lfs *LocalFSHandler) OpenFile(path string) (string, error) {
	// Path validation handled in Set()
	var anpath LocalAnPath
	err := anpath.Set(path)
	if err != nil {
		return "", err
	}

	handle, err := os.Open(anpath.ProviderPath())
	if err != nil {
		return "", err
	}

	var providerHandle LocalFSHandle
	providerHandle.Path = anpath.ProviderPath()
	providerHandle.Handle = handle
	lfs.Files[path] = providerHandle

	return anpath.MensagoPath(), nil
}

// ReadFile reads data from a file opened with OpenFile. If the Read() call encounters the end of
// the file, less data than specified will be returned and the file handle will automatically be
// closed.
func (lfs *LocalFSHandler) ReadFile(handle string, buffer []byte) (int, error) {

	lfsh, exists := lfs.Files[handle]
	if !exists {
		return 0, os.ErrNotExist
	}

	bytesRead, err := lfsh.Handle.Read(buffer)
	if err == io.EOF {
		lfsh.Handle.Close()
		delete(lfs.Files, handle)
	}
	return bytesRead, err
}

// RemoveDirectory creates a directory in the local filesystem relative to the workspace folder
func (lfs *LocalFSHandler) RemoveDirectory(path string, recursive bool) error {

	// Path validation handled in FromPath()
	var anpath LocalAnPath
	err := anpath.Set(path)
	if err != nil {
		return err
	}

	stat, err := os.Stat(anpath.LocalPath)
	if err != nil {
		return err
	}
	if !stat.IsDir() {
		return errors.New("directory path is a file")
	}

	if recursive {
		return os.RemoveAll(anpath.LocalPath)
	}
	return os.Remove(anpath.LocalPath)
}

// Select confirms that the given path is a valid working directory for the user
func (lfs *LocalFSHandler) Select(path string) (LocalAnPath, error) {

	// Path validation handled in FromPath()
	var anpath LocalAnPath
	err := anpath.Set(path)
	if err != nil {
		return anpath, err
	}

	stat, err := os.Stat(anpath.LocalPath)
	if err != nil {
		return anpath, err
	}
	if !stat.IsDir() {
		return anpath, errors.New("directory path is a file")
	}

	return anpath, nil
}

// RemoveWorkspace deletes all file and folder data for the specified workspace. This call does
// not validate the workspace string. Validation is the caller's responsibility.
func RemoveWorkspace(wid string) error {
	allWorkspacesRoot := viper.GetString("global.workspace_dir")
	if len(allWorkspacesRoot) < 1 {
		return errors.New("empty workspace path")
	}

	stat, err := os.Stat(allWorkspacesRoot)
	if err != nil {
		return err
	}
	if !stat.IsDir() {
		return errors.New("workspace path is a file")
	}

	workspaceRoot := filepath.Join(allWorkspacesRoot, wid)
	return os.RemoveAll(workspaceRoot)
}
