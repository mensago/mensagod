package keycard_cache

import (
	"github.com/darkwyrm/mensagod/dbhandler"
	"github.com/darkwyrm/mensagod/keycard"
	"github.com/darkwyrm/mensagod/misc"
)

func GetKeycard(address string) (*keycard.Keycard, error) {

	// TODO: Implement GetKeycard
	return nil, misc.ErrUnimplemented
}

// ResolveAddress takes a Mensago address and returns the workspace address. Unlike the function
// in dbhandler, this version handles external addresses.
func ResolveAddress(address string) (string, error) {

	// Quickly resolve local addresses
	out, err := dbhandler.ResolveAddress(address)
	if err == nil {
		return out, nil
	}

	// The only error code we don't care about is if the local resolver could not find the address,
	// which means the address is external
	if err != misc.ErrNotFound {
		return "", err
	}

	// TODO: Finish implementing ResolveAddress
	return "", misc.ErrUnimplemented
}
