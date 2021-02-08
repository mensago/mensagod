package fshandler

import "errors"

// AnPath encapsulates all the translation between a standard Anselus path into whatever format
// a filesystem needs. These are leveraged by the filesytem providers to assist with going between
// the two realms
type AnPath interface {
	ToProvider(path string) (string, error)
	FromProvider(path string) (string, error)
}

// LocalAnPath is an AnPath interface that interacts with the local filesystem. It handles the
// operating system-specific path separators, among other things.
type LocalAnPath struct {
	// Path contains the path as formatted for the Anselus platform
	Path string

	// LocalPath holds the path as needed by the local filesystem
	LocalPath string
}

// ToProvider translates an Anselus path to the local filesystem
func (ap *LocalAnPath) ToProvider(path string) (string, error) {
	return "", errors.New("unimplemented")
}

// FromProvider translates a local filesystem path to an Anselus path
func (ap *LocalAnPath) FromProvider(path string) (string, error) {
	return "", errors.New("unimplemented")
}
