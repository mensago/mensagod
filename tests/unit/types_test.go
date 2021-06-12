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
	if wid.Set("aaaaaaaa-BBBB-1111-1111-111111111111") != nil {
		t.Fatal("UUID.Set failed a valid UUID")
	}
	if string(wid) != "aaaaaaaa-bbbb-1111-1111-111111111111" {
		t.Fatal("UUID.Set failed to squash case")
	}
}
