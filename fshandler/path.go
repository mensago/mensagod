package fshandler

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/viper"
)

// AnPath encapsulates all the translation between a standard Anselus path into whatever format
// a filesystem needs. These are leveraged by the filesytem providers to assist with going between
// the two realms
type AnPath interface {
	Set(path string) error
	ProviderPath() string
	AnselusPath() string
}

// LocalAnPath is an AnPath interface that interacts with the local filesystem. It handles the
// operating system-specific path separators, among other things.
type LocalAnPath struct {
	// Path contains the path as formatted for the Anselus platform
	Path string

	// LocalPath holds the path as needed by the local filesystem
	LocalPath string
}

// NewLocalPath creates a new LocalAnPath object
func NewLocalPath() *LocalAnPath {
	var out LocalAnPath
	return &out
}

// Set assigns an Anselus path to the object
func (ap *LocalAnPath) Set(path string) error {

	if path == "" {
		ap.LocalPath = ""
		ap.Path = ""
		return nil
	}

	if !ValidateAnselusPath(path) {
		return errors.New("invalid path")
	}

	ap.Path = path

	workspaceRoot := viper.GetString("global.workspace_dir")
	pathParts := strings.Split(path, " ")
	ap.LocalPath = filepath.Join(workspaceRoot,
		strings.Join(pathParts[1:], string(filepath.Separator)))

	return nil
}

// ProviderPath returns the local filesystem version of the path set
func (ap *LocalAnPath) ProviderPath() string {
	return ap.LocalPath
}

// AnselusPath returns the Anselus path version of the path set
func (ap *LocalAnPath) AnselusPath() string {
	return ap.Path
}

// ValidateAnselusPath confirms the validity of an Anselus path
func ValidateAnselusPath(path string) bool {
	pattern := regexp.MustCompile(
		"^/( [0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12})*$")
	return pattern.MatchString(path)
}

// ValidateFileName returns whether or not a filename conforms to the format expected by the
// platform
func ValidateFileName(filename string) bool {
	pattern := regexp.MustCompile(
		"^[0-9]+\\.[0-9]+\\.[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$")
	return pattern.MatchString(filename)
}

// GenerateFileName creates a filename matching the format expected by the Anselus platform
func GenerateFileName(filesize int) string {
	return fmt.Sprintf("%d.%d.%s", time.Now().Unix(), filesize, uuid.New().String())
}
