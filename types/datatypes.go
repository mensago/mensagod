// Package for shared data types
package types

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/darkwyrm/mensagod/misc"
)

// For when a Mensago address or a workspace address is acceptable
type MAddress struct {
	IDType uint8
	ID     string
	Domain DomainT
}

// For when you *must* have a workspace address
type WAddress struct {
	ID     UUID
	Domain DomainT
}

type UserID string
type UUID string
type DomainT string

var widPattern = regexp.MustCompile(`[\da-fA-F]{8}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{12}`)
var uidPattern1 = regexp.MustCompile("[[:space:]]+")
var uidPattern2 = regexp.MustCompile("[\\\\/\"]")
var domainPattern = regexp.MustCompile("^([a-zA-Z0-9\\-]+\x2E)+[a-zA-Z0-9\\-]+$")

// IsWorkspace returns true if the ID is a workspace ID, not a user ID
func (a MAddress) IsWorkspace() bool {
	return a.IDType == 1
}

func (a MAddress) IsValid() bool {

	switch a.IDType {
	// Workspace address
	case 1:
		if len(a.ID) != 36 {
			return false
		}
		return widPattern.MatchString(a.ID) && domainPattern.MatchString(string(a.Domain))
	// Mensago address
	case 2:
		if uidPattern1.MatchString(a.ID) || uidPattern2.MatchString(a.ID) {
			return false
		}

		if utf8.RuneCountInString(a.ID) <= 64 && domainPattern.MatchString(string(a.Domain)) {
			return true
		}
	// uninitialized or bad type
	default:
	}
	return false
}

func (a MAddress) GetID() string {
	return string(a.ID)
}

func (a MAddress) GetDomain() string {
	return string(a.Domain)
}

func (a MAddress) GetAddress() string {
	if a.ID == "" || a.Domain == "" {
		return ""
	}
	return a.ID + "/" + string(a.Domain)
}

func (a *MAddress) Set(addr string) error {
	parts := strings.SplitN(addr, "/", 2)
	if len(parts) != 2 {
		return misc.ErrBadArgument
	}

	tempWID := ToUUID(parts[0])
	if tempWID.IsValid() {
		a.ID = parts[0]
		a.Domain.Set(parts[1])
		a.IDType = 1
		return nil
	}

	tempUID := ToUserID(parts[0])
	if tempUID.IsValid() {
		a.ID = parts[0]
		a.Domain.Set(parts[1])
		a.IDType = 2
		return nil
	}

	a.ID = ""
	a.Domain.Set("")
	a.IDType = 0
	return misc.ErrBadArgument
}

func ToMAddress(addr string) MAddress {
	var out MAddress
	out.Set(addr)
	return out
}

func (a WAddress) IsValid() bool {
	if len(a.ID) != 36 {
		return false
	}
	return widPattern.MatchString(string(a.ID)) && domainPattern.MatchString(string(a.Domain))
}

func (a WAddress) GetID() string {
	return string(a.ID)
}

func (a WAddress) GetDomain() string {
	return string(a.Domain)
}

func (a WAddress) GetAddress() string {
	if a.ID == "" || a.Domain == "" {
		return ""
	}
	return string(a.ID) + "/" + string(a.Domain)
}

func (a WAddress) AsMAddress() MAddress {
	var out MAddress
	out.ID = a.ID.AsString()
	out.Domain = a.Domain
	out.IDType = 1
	return out
}

func (a *WAddress) Set(addr string) error {
	parts := strings.SplitN(strings.ToLower(addr), "/", 1)
	if len(parts) != 2 {
		return misc.ErrBadArgument
	}
	if !widPattern.MatchString(parts[0]) || !ValidateDomain(parts[1]) {
		a.Domain = ""
		a.ID = ""
		return misc.ErrBadArgument
	}
	a.ID.Set(parts[0])
	a.Domain.Set(parts[1])
	return nil
}

func ToWAddress(addr string) WAddress {
	var out WAddress
	out.Set(addr)
	return out
}

func (uid UserID) IsValid() bool {

	if uidPattern1.MatchString(string(uid)) || uidPattern2.MatchString(string(uid)) ||
		len(uid) == 0 {
		// if uidPattern1.MatchString(string(uid)) || uidPattern2.MatchString(string(uid)) {
		return false
	}

	fmt.Printf("String: %s, Rune Count: %d\n", string(uid), utf8.RuneCountInString(string(uid)))
	return utf8.RuneCountInString(string(uid)) <= 64
}

func (uid UserID) AsString() string {
	return string(uid)
}

func (uid *UserID) Set(data string) error {
	*uid = UserID(strings.TrimSpace(strings.ToLower(data)))

	if uid.IsValid() {
		return nil
	}

	*uid = ""
	return misc.ErrBadArgument
}

func ToUserID(addr string) UserID {
	var out UserID
	out.Set(addr)
	return out
}

func (wid UUID) IsValid() bool {
	return widPattern.MatchString(string(wid))
}

func (wid UUID) AsString() string {
	return string(wid)
}

func (wid *UUID) Set(data string) error {
	*wid = UUID(strings.TrimSpace(strings.ToLower(data)))

	if wid.IsValid() {
		return nil
	}

	*wid = ""
	return misc.ErrBadArgument
}

func ToUUID(addr string) UUID {
	var out UUID
	out.Set(addr)
	return out
}

func (dom DomainT) IsValid() bool {
	return domainPattern.MatchString(string(dom))
}

func (dom DomainT) AsString() string {
	return string(dom)
}

func (dom *DomainT) Set(data string) error {
	*dom = DomainT(strings.TrimSpace(strings.ToLower(data)))

	if dom.IsValid() {
		return nil
	}

	*dom = ""
	return misc.ErrBadArgument
}

func ToDomain(addr string) DomainT {
	var out DomainT
	out.Set(addr)
	return out
}

func ValidateDomain(domain string) bool {
	return domainPattern.MatchString(domain)
}
