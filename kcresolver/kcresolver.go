package kcresolver

import (
	"container/list"
	"errors"
	"strings"
	"sync"

	"github.com/spf13/viper"
	"gitlab.com/mensago/mensagod/dbhandler"
	"gitlab.com/mensago/mensagod/keycard"
	"gitlab.com/mensago/mensagod/misc"
	"gitlab.com/mensago/mensagod/types"
)

type cacheItem struct {
	Card      *keycard.Keycard
	QueueItem *list.Element
}

type keycardCache struct {
	Items     map[string]*cacheItem
	ItemQueue *list.List
	Lock      sync.RWMutex
	Capacity  int
}

var cardCache keycardCache

func InitCache() {
	cardCache.Items = make(map[string]*cacheItem)
	cardCache.Capacity = viper.GetInt("performance.kcresolver_size")
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

	c.Lock.Lock()
	defer c.Lock.Unlock()

	// If the queue is at capacity, pop the last one off the back
	if len(c.Items) == c.Capacity {
		lastElement := c.ItemQueue.Back()
		lastItem, ok := c.ItemQueue.Remove(lastElement).(*cacheItem)
		if !ok {
			return errors.New("bug: interface cast failure in keycardCache.Queue")
		}

		waddr := strings.Join([]string{lastItem.Card.Entries[0].Fields["Workspace-ID"], "/",
			lastItem.Card.Entries[0].Fields["Domain"]}, "")
		delete(cardCache.Items, waddr)
	}

	var newItem cacheItem
	newItem.QueueItem = c.ItemQueue.PushFront(&newItem)
	newItem.Card = card.Duplicate()

	var owner string
	if card.Type == "Organization" {
		owner = card.Entries[0].Fields["Domain"]
	} else {
		owner = strings.Join([]string{card.Entries[0].Fields["Workspace-ID"], "/",
			card.Entries[0].Fields["Domain"]}, "")
	}
	c.Items[owner] = &newItem

	return nil
}

func GetKeycard(address types.MAddress, cardType string) (*keycard.Keycard, error) {

	var out keycard.Keycard

	if cardType != "User" && cardType != "Organization" {
		return nil, misc.ErrBadArgument
	}

	waddr, err := ResolveAddress(address)
	if err != nil {
		return nil, err
	}

	// In this case, if we got some other error besides ErrNotFound, we definitely want to return
	// here. At the same time, if we have success
	out, err = cardCache.GetCard(waddr.AsString())
	if err != misc.ErrNotFound {
		return &out, err
	}

	// Card not in the cache, so begin the actual lookup
	isLocal, err := dbhandler.IsDomainLocal(address.Domain)
	if err != nil {
		return nil, err
	}

	if isLocal {
		if cardType == "User" {
			out, err = dbhandler.GetUserKeycard(types.UUID(waddr.ID))
		} else {
			out, err = dbhandler.GetOrgKeycard()
		}
		if err != nil {
			return nil, err
		}

		cardCache.Queue(&out)
		return &out, nil
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
func ResolveAddress(address types.MAddress) (types.WAddress, error) {
	var out types.WAddress

	// Quickly resolve local addresses
	localAddr, err := dbhandler.ResolveAddress(address)
	if err == nil {
		out.ID = localAddr
		return out, nil
	}

	// The only error code we don't care about is if the local resolver could not find the address,
	// which means the address is external
	if err != misc.ErrNotFound {
		return out, err
	}

	// TODO: POSTDEMO: Implement external resolution in kcresolver.ResolveAddress
	return out, misc.ErrUnimplemented
}
