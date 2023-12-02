package mensagod

import (
	"testing"

	"gitlab.com/mensago/mensagod/types"
)

func TestMAddressSet(t *testing.T) {
	var addr types.MAddress

	addresses := []string{
		"admin/example.com",
		"alsogoooood/example.net",
		"🐧/example.org",
		"ಅಎಇ/example.com",
		"11111111-1111-1111-1111-111111111111/example.net",
		" aaaaaaaa-BBBB-1111-1111-111111111111/example.org",
	}

	for _, teststr := range addresses {
		if addr.Set(teststr) != nil {
			t.Fatalf("MAddress.Set failed a valid Mensago address: %s", teststr)
		}
	}

	addresses = []string{
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/foo.com",
		"John Q. Public/example.com",
	}

	for _, teststr := range addresses {
		if addr.Set(teststr) == nil {
			t.Fatalf("MAddress.Set passed an invalid Mensago address: %s", teststr)
		}
	}
}

func TestUUIDIsValid(t *testing.T) {
	wid := types.RandomID("11111111-1111-1111-1111-111111111111")
	if !wid.IsValid() {
		t.Fatalf("UUID.IsValid failed a valid UUID")
	}

	wid = types.RandomID("11111111111111111111111111111111")
	if wid.IsValid() {
		t.Fatal("UUID.IsValid passed a UUID without dashes")
	}
}

func TestUUIDSet(t *testing.T) {
	var wid types.RandomID
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
