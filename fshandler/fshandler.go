package fshandler

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

// This module is for abstracting away all the messy details of interacting with the filesystem

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
