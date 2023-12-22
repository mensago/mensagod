// Package for shared data types
package types

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"gitlab.com/mensago/mensagod/misc"
)

// For when a Mensago address or a workspace address is acceptable
type MAddress struct {
	IDType uint8
	ID     string
	Domain DomainT
}

// For when you *must* have a workspace address
type WAddress struct {
	ID     RandomID
	Domain DomainT
}

type UserID string
type RandomID string
type DomainT string

var widPattern = regexp.MustCompile(`^[\da-fA-F]{8}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{12}$`)
var uidPattern = regexp.MustCompile(`^([\w\-]|\.[^.]){0,65}$`)
var domainPattern = regexp.MustCompile("^([a-zA-Z0-9\\-]+\x2E)+[a-zA-Z0-9\\-]+$")

// ------------------------------------------------------------------------------------------------

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
		if uidPattern.MatchString(a.ID) {
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

func (a MAddress) AsString() string {
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

	_, err := ToRandomID(parts[0])
	if err == nil {
		if err = a.Domain.Set(parts[1]); err != nil {
			return err
		}
		a.ID = parts[0]
		a.IDType = 1
		return nil
	}

	_, err = ToUserID(parts[0])
	if err == nil {
		if err = a.Domain.Set(parts[1]); err != nil {
			return err
		}
		a.ID = parts[0]
		a.IDType = 2
		return nil
	}

	a.ID = ""
	a.Domain.Set("")
	a.IDType = 0
	return misc.ErrBadArgument
}

func (a MAddress) Equals(other MAddress) bool {
	return a.IDType == other.IDType && a.ID == other.ID && a.Domain.Equals(other.Domain)
}

func ToMAddress(addr string) (MAddress, error) {
	var out MAddress
	err := out.Set(addr)
	return out, err
}

func ToMAddressFromParts(uid UserID, dom DomainT) MAddress {
	var out MAddress

	if uid.IsWID() {
		out.IDType = 1
	} else {
		out.IDType = 2
	}
	out.ID = uid.AsString()
	out.Domain = dom
	return out
}

// ------------------------------------------------------------------------------------------------

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

func (a WAddress) AsString() string {
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

func (a WAddress) Equals(other WAddress) bool {
	return a.ID.Equals(other.ID) && a.Domain.Equals(other.Domain)
}

func ToWAddress(addr string) WAddress {
	var out WAddress
	out.Set(addr)
	return out
}

// ------------------------------------------------------------------------------------------------

func (uid UserID) IsValid() bool {

	if len(uid) == 0 || !uidPattern.MatchString(string(uid)) {
		return false
	}

	return utf8.RuneCountInString(string(uid)) <= 64
}

// Workspace ID's are also valid user IDs
func (uid UserID) IsWID() bool {
	return widPattern.MatchString(string(uid))
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

func (uid UserID) Equals(other UserID) bool {
	return string(uid) == string(other)
}

func ToUserID(addr string) (UserID, error) {
	var out UserID
	err := out.Set(addr)
	return out, err
}

// ------------------------------------------------------------------------------------------------

func NewRandomID() (RandomID, error) {
	var out RandomID
	newid, err := uuid.NewRandom()
	if err != nil {
		return out, err
	}

	err = out.Set(newid.String())
	if err != nil {
		return out, err
	}

	return out, nil
}

func (wid RandomID) IsValid() bool {
	return widPattern.MatchString(string(wid))
}

func (wid RandomID) AsString() string {
	return string(wid)
}

func (wid *RandomID) Set(data string) error {
	*wid = RandomID(strings.TrimSpace(strings.ToLower(data)))

	if wid.IsValid() {
		return nil
	}

	*wid = ""
	return misc.ErrBadArgument
}

func (wid RandomID) Equals(other RandomID) bool {
	return string(wid) == string(other)
}

func ToRandomID(addr string) (RandomID, error) {
	var out RandomID
	if err := out.Set(addr); err != nil {
		return out, err
	}
	return out, nil
}

func RandomIDString() string {
	return strings.TrimSpace(strings.ToLower(uuid.NewString()))
}

// ------------------------------------------------------------------------------------------------

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

func (dom DomainT) Equals(other DomainT) bool {
	return string(dom) == string(other)
}

func ToDomain(addr string) DomainT {
	var out DomainT
	out.Set(addr)
	return out
}

func ValidateDomain(domain string) bool {
	return domainPattern.MatchString(domain)
}
