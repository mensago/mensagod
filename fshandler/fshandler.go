package fshandler

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/darkwyrm/anselusd/logging"
	"github.com/spf13/viper"
)

// This module is for abstracting away all the messy details of interacting with the filesystem

// FSProvider objects have a standardized interface for interacting with a filesystem so that
// working with a BackBlaze B2 bucket is just as easy as the local filesystem
type FSProvider interface {
	ProviderName() string
	ProviderType() string

	Exists(path string) error
	MakeDirectory(path string) error
	RemoveDirectory(path string, recursive bool) error
	ListFiles(path string, afterTime int64) ([]string, error)
	ListDirectories(path string) ([]string, error)

	MakeTempFile(wid string) (*os.File, error)
	InstallTempFile(source *os.File, dest string) error

	MoveFile(source string, dest string) error
	CopyFile(source string, dest string) (string, error)
	DeleteFile(path string) error
	OpenFile(path string) (string, error)
	ReadFile(handle string, size int) ([]byte, error)
	CloseFile(handle string) error
}

// LocalFSProvider represents local storage on the server
type LocalFSProvider struct {
	BasePath      string
	PathSeparator string
}

// ProviderName returns the name of the filesystem provider
func (lfs *LocalFSProvider) ProviderName() string {
	return "LocalFS"
}

// NewLocalProvider returns a new filesystem provider which interacts with the local filesystem.
// It obtains the necessary information about the local filesystem directly from the server
// configuration data.
func NewLocalProvider() *LocalFSProvider {
	var provider LocalFSProvider

	provider.BasePath = viper.GetString("global.workspace_dir")

	switch runtime.GOOS {
	case "windows":
		provider.PathSeparator = "\\"
	default:
		provider.PathSeparator = "/"
	}

	return &provider
}

// ProviderType returns the type of the filesystem handled by the provider. Currently the only
// values returned by this are either 'local' or 'cloud'. More detail can be provided by adding
// a subtype following a period, such as 'cloud.azure' or 'cloud.b2'.
func (lfs *LocalFSProvider) ProviderType() string {
	return "local"
}

// Exists checks to see if the specified path exists
func (lfs *LocalFSProvider) Exists(path string) (bool, error) {

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

// MakeDirectory creates a directory in the local filesystem relative to the workspace folder
func (lfs *LocalFSProvider) MakeDirectory(path string) error {

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

// RemoveDirectory creates a directory in the local filesystem relative to the workspace folder
func (lfs *LocalFSProvider) RemoveDirectory(path string, recursive bool) error {

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

// ListFiles returns all files in the specified path after the specified time. Note that the time
// is in UNIX time, i.e. seconds since the epoch. To return all files, pass a 0.
func (lfs *LocalFSProvider) ListFiles(path string, afterTime int64) ([]string, error) {
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

	handle, err := os.Open(path)
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

// ListDirectories returns the names of all subdirectories of the specified path
func (lfs *LocalFSProvider) ListDirectories(path string) ([]string, error) {
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

	handle, err := os.Open(path)
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

// MakeTempFile creates a file in the temporary file area and returns a handle to it. The caller is
// responsible for closing the handle when finished.
func (lfs *LocalFSProvider) MakeTempFile(wid string) (*os.File, string, error) {

	// TODO: validate WID

	tempDirPath := filepath.Join(viper.GetString("global.workspace_dir"), "tmp")

	// TODO: ensure workspace temp directory exists

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

	handle, err := os.OpenFile(tempFilePath, os.O_RDWR, 0600)
	if err != nil {
		logging.Writef("Couldn't save temp file %s: %s", tempFilePath, err.Error())
		return nil, "", err
	}

	return handle, tempFileName, nil
}

// InstallTempFile moves a file from the temporary file area to its location in a workspace
func (lfs *LocalFSProvider) InstallTempFile(source string, dest string) error {
	return errors.New("unimplemented")
}

// MoveFile moves the specified file to the specified directory. Note that dest MUST point to
// a directory.
func (lfs *LocalFSProvider) MoveFile(source string, dest string) error {
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
	_, err = os.Stat(srcAnpath.ProviderPath())
	if err == nil {
		return errors.New("source exists in destination path")
	}
	err = os.Rename(srcAnpath.ProviderPath(), newPath)

	return err
}

// CopyFile creates a duplicate of the specified source file in the specified destination folder
// and returns the name of the new file
func (lfs *LocalFSProvider) CopyFile(source string, dest string) (string, error) {
	return "", errors.New("unimplemented")
}

// DeleteFile deletes the specified workspace file
func (lfs *LocalFSProvider) DeleteFile(path string) error {
	return errors.New("unimplemented")
}

// OpenFile opens the specified file for reading data and returns a file handle as a string. The
// contents of the handle are specific to the provider and should not be expected to follow any
// particular format
func (lfs *LocalFSProvider) OpenFile(path string) (string, error) {
	return "", errors.New("unimplemented")
}

// ReadFile reads data from a file opened with OpenFile. If the Read() call encounters the end of
// the file, less data than specified will be returned and the file handle will automatically be
// closed.
func (lfs *LocalFSProvider) ReadFile(handle string, size int) ([]byte, error) {
	return nil, errors.New("unimplemented")
}

// CloseFile closes the specified file handle. It is not normally needed unless Read() returns an
// error or the caller must abort reading the file.
func (lfs *LocalFSProvider) CloseFile(handle string) error {
	return errors.New("unimplemented")
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
