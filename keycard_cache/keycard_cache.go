package keycard_cache

import (
	"container/list"
	"sync"

	"github.com/darkwyrm/mensagod/dbhandler"
	"github.com/darkwyrm/mensagod/keycard"
	"github.com/darkwyrm/mensagod/misc"
	"github.com/darkwyrm/mensagod/types"
	"github.com/spf13/viper"
)

type cacheItem struct {
	Card      *keycard.Keycard
	QueueItem *list.Element
}

type keycardCache struct {
	Items     map[string]*cacheItem
	ItemQueue *list.List
	Lock      sync.RWMutex
	Capacity  int64
}

var cardCache keycardCache

func InitCache() {
	cardCache.Items = make(map[string]*cacheItem)
	cardCache.Capacity = viper.GetInt64("performance.keycard_cache_size")
	cardCache.ItemQueue = list.New()
}

func (c *keycardCache) GetCard(owner string) (keycard.Keycard, error) {

	var item *cacheItem

	c.Lock.RLock()
	item, exists := c.Items[owner]
	if !exists {
		defer c.Lock.RUnlock()
		return keycard.Keycard{}, misc.ErrNotFound
	}
	c.Lock.RUnlock()

	c.Lock.Lock()
	defer c.Lock.Unlock()

	c.ItemQueue.MoveToFront(item.QueueItem)

	out := item.Card.Duplicate()
	return *out, misc.ErrUnimplemented
}

func (c *keycardCache) Queue(card *keycard.Keycard) error {

	// Implement cardCache.Queue()
	return misc.ErrUnimplemented
}

func GetKeycard(address types.Address, cardType string) (keycard.Keycard, error) {

	var out keycard.Keycard

	// TODO: Finish implementing GetKeycard

	if cardType != "User" && cardType != "Organization" {
		return out, misc.ErrBadArgument
	}

	waddr, err := ResolveAddress(address)
	// _, err := ResolveAddress(address)
	if err != nil {
		return out, err
	}

	// TODO: check cache for card

	// Card not in the cache, so begin the actual lookup
	isLocal, err := dbhandler.IsDomainLocal(address.AsString())
	if err != nil {
		return out, err
	}

	if isLocal {
		if cardType == "User" {
			out, err = dbhandler.GetUserKeycard(waddr.AsString())
		} else {
			out, err = dbhandler.GetOrgKeycard()
		}
		if err != nil {
			return out, err
		}

		// TODO: convert to use pointers internally
		// TODO: add card to cache

		return out, nil
	}

	// TODO: POSTDEMO: implement external keycard resolution

	// This shouldn't be hard.
	// - connect to server
	// - call GETENTRY and download entries
	// - convert entries to card
	// - add card to cache and return copy

	return out, misc.ErrUnimplemented
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
