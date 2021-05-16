// Package for shared data types
package types

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/darkwyrm/mensagod/misc"
)

type Address struct {
	IDType uint8
	ID     string
	Domain string
}

var widPattern = regexp.MustCompile(`[\da-fA-F]{8}-?[\da-fA-F]{4}-?[\da-fA-F]{4}-?[\da-fA-F]{4}-?[\da-fA-F]{12}`)
var uidPattern1 = regexp.MustCompile("[[:space:]]+")
var uidPattern2 = regexp.MustCompile("[\\\\/\"]")

// IsWorkspace returns true if the ID is a workspace ID, not a user ID
func (a Address) IsWorkspace() bool {
	return a.IDType == 1
}

func (a Address) IsValid() bool {

	switch a.IDType {
	// Workspace address
	case 1:
		if len(a.ID) != 36 && len(a.ID) != 32 {
			return false
		}
		return widPattern.MatchString(a.ID)
	// Mensago address
	case 2:
		if uidPattern1.MatchString(a.ID) || uidPattern2.MatchString(a.ID) {
			return false
		}

		if utf8.RuneCountInString(a.ID) <= 64 {
			return true
		}
	// uninitialized or bad type
	default:
	}
	return false
}

func (a Address) AsString() string {
	if a.ID == "" || a.Domain == "" {
		return ""
	}
	return a.ID + "/" + a.Domain
}

func (a *Address) Set(addr string) error {
	parts := strings.SplitN(addr, "/", 1)
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
