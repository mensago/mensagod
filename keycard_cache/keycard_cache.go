package keycard_cache

import (
	"sync"
	"time"

	"github.com/darkwyrm/mensagod/dbhandler"
	"github.com/darkwyrm/mensagod/keycard"
	"github.com/darkwyrm/mensagod/misc"
	"github.com/darkwyrm/mensagod/types"
	"github.com/spf13/viper"
)

type cardCacheItem struct {
	Card        keycard.Keycard
	LastUpdated time.Time
}

var cardCache map[string]cardCacheItem
var cacheLock sync.RWMutex
var cacheCapacity int64

func InitCache() {
	cacheCapacity = viper.GetInt64("performance.keycard_cache_size")
	cardCache = make(map[string]cardCacheItem)
}

func GetKeycard(address types.Address, cardType string) (*keycard.Keycard, error) {

	// TODO: Finish implementing GetKeycard

	if cardType != "User" && cardType != "Organization" {
		return nil, misc.ErrBadArgument
	}

	// waddr, err := ResolveAddress(address)
	_, err := ResolveAddress(address)
	if err != nil {
		return nil, err
	}

	// TODO: check cache for card

	// Card not in the cache, so begin the actual lookup
	isLocal, err := dbhandler.IsDomainLocal(address.AsString())
	if err != nil {
		return nil, err
	}

	if isLocal {
		// TODO: get entries from database and convert to card

		// - call dbhandler.GetOrgEntries or GetUserEntries as appropriate
		// - convert entries to card
		// - add card to cache and return copy
		return nil, misc.ErrUnimplemented
	}

	// TODO: POSTDEMO: implement external keycard resolution

	// This shouldn't be hard.
	// - connect to server
	// - call GETENTRY and download entries
	// - convert entries to card
	// - add card to cache and return copy

	return nil, misc.ErrUnimplemented
}

// ResolveAddress takes a Mensago address and returns the workspace address. Unlike the function
// in dbhandler, this version handles external addresses.
func ResolveAddress(address types.Address) (types.Address, error) {
	var out types.Address

	// Quickly resolve local addresses
	tempString, err := dbhandler.ResolveAddress(address.AsString())
	if err == nil {
		out.Set(tempString)
		return out, nil
	}

	// The only error code we don't care about is if the local resolver could not find the address,
	// which means the address is external
	if err != misc.ErrNotFound {
		return out, err
	}

	// TODO: Finish implementing ResolveAddress
	return out, misc.ErrUnimplemented
}

func convertEntriesToObject([]string) (*keycard.Keycard, error) {

	// TODO: Implement convertEntriesToObject
	return nil, misc.ErrUnimplemented
}
