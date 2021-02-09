package fshandler

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"

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
	anpath := NewLocalPath()
	err := anpath.Set(path)
	if err != nil {
		return false, err
	}

	_, err = os.Stat(anpath.LocalPath)
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

	// Path validation handled in Set()
	anpath := NewLocalPath()
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

	// Path validation handled in Set()
	anpath := NewLocalPath()
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
