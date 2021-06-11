// Package for shared data types
package types

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/darkwyrm/mensagod/misc"
)

// For when a Mensago address or a workspace address is acceptable
type MAddress struct {
	IDType uint8
	ID     string
	Domain string
}

// For when you *must* have a workspace address
type WAddress struct {
	ID     string
	Domain string
}

var widPattern = regexp.MustCompile(`[\da-fA-F]{8}-?[\da-fA-F]{4}-?[\da-fA-F]{4}-?[\da-fA-F]{4}-?[\da-fA-F]{12}`)
var uidPattern1 = regexp.MustCompile("[[:space:]]+")
var uidPattern2 = regexp.MustCompile("[\\\\/\"]")
var domainPattern = regexp.MustCompile("([a-zA-Z0-9]+\x2E)+[a-zA-Z0-9]+")

// IsWorkspace returns true if the ID is a workspace ID, not a user ID
func (a MAddress) IsWorkspace() bool {
	return a.IDType == 1
}

func (a MAddress) IsValid() bool {

	switch a.IDType {
	// Workspace address
	case 1:
		if len(a.ID) != 36 && len(a.ID) != 32 {
			return false
		}
		return widPattern.MatchString(a.ID) && domainPattern.MatchString(a.Domain)
	// Mensago address
	case 2:
		if uidPattern1.MatchString(a.ID) || uidPattern2.MatchString(a.ID) {
			return false
		}

		if utf8.RuneCountInString(a.ID) <= 64 && domainPattern.MatchString(a.Domain) {
			return true
		}
	// uninitialized or bad type
	default:
	}
	return false
}

func (a MAddress) AsString() string {
	if a.ID == "" || a.Domain == "" {
		return ""
	}
	return a.ID + "/" + a.Domain
}

func (a *MAddress) Set(addr string) error {
	parts := strings.SplitN(strings.ToLower(addr), "/", 1)
	if len(parts) != 2 {
		return misc.ErrBadArgument
	}
	a.ID = parts[0]
	a.Domain = parts[1]

	if !a.IsValid() {
		a.IDType = 0
		return misc.ErrBadArgument
	}

	if widPattern.MatchString(a.ID) {
		a.IDType = 1
	} else {
		a.IDType = 2
	}
	return nil
}

func (a WAddress) IsValid() bool {
	if len(a.ID) != 36 && len(a.ID) != 32 {
		return false
	}
	return widPattern.MatchString(a.ID) && domainPattern.MatchString(a.Domain)
}

func (a WAddress) AsString() string {
	if a.ID == "" || a.Domain == "" {
		return ""
	}
	return a.ID + "/" + a.Domain
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
	a.ID = parts[0]
	a.Domain = parts[1]
	return nil
}

func ValidateDomain(domain string) bool {
	return domainPattern.MatchString(domain)
}
