package mensagod

import (
	"testing"

	"github.com/darkwyrm/mensagod/types"
)

func TestUUIDIsValid(t *testing.T) {
	wid := types.UUID("11111111-1111-1111-1111-111111111111")
	if !wid.IsValid() {
		t.Fatalf("UUID.IsValid failed a valid UUID")
	}

	wid = types.UUID("11111111111111111111111111111111")
	if wid.IsValid() {
		t.Fatal("UUID.IsValid passed a UUID without dashes")
	}
}

func TestUUIDSet(t *testing.T) {
	var wid types.UUID
	if wid.Set(" aaaaaaaa-BBBB-1111-1111-111111111111") != nil {
		t.Fatal("UUID.Set failed a valid UUID")
	}
	if string(wid) != "aaaaaaaa-bbbb-1111-1111-111111111111" {
		t.Fatal("UUID.Set failed to squash case and trim space")
	}
}

func TestDomainIsValid(t *testing.T) {
	dom := types.DomainT("foo-bar.baz.com")
	if !dom.IsValid() {
		t.Fatalf("DomainT.IsValid failed a valid UUID")
	}

	dom = types.DomainT("foo-bar..baz.com")
	if dom.IsValid() {
		t.Fatal("DomainT.IsValid passed a bad domain")
	}
}

func TestDomainSet(t *testing.T) {
	var dom types.DomainT
	if dom.Set("FOO.bar.com ") != nil {
		t.Fatal("DomainT.Set failed a valid domain")
	}
	if string(dom) != "foo.bar.com" {
		t.Fatal("DomainT.Set failed to squash case and trim spaces")
	}
}

func TestUserIDIsValid(t *testing.T) {
	uid := types.UserID("cavs4life")
	if !uid.IsValid() {
		t.Fatalf("UserID.IsValid failed a valid user ID")
	}

	uid = types.UserID("a bad ID")
	if uid.IsValid() {
		t.Fatal("UserID.IsValid passed a bad domain")
	}
}

func TestUserIDSet(t *testing.T) {
	var uid types.UserID

	for _, teststr := range []string{"GoodID", "alsogoooood", "🐧", "ಅಎಇ"} {
		if uid.Set(teststr) != nil {
			t.Fatalf("UserID.Set failed a valid user ID: %s", teststr)
		}
	}

	for _, teststr := range []string{"a bad id", "also/bad"} {
		if uid.Set(teststr) == nil {
			t.Fatalf("UserID.Set passed an invalid user ID: %s", teststr)
		}
	}

	uid.Set(" FOO.BAR.com ")
	if string(uid) != "foo.bar.com" {
		t.Fatal("UserID.Set failed to squash case and trim spaces")
	}
}
