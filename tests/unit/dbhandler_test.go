package mensagod

import (
	"testing"

	"github.com/darkwyrm/mensagod/dbhandler"
)

func TestValidateUUID(t *testing.T) {
	if !dbhandler.ValidateUUID("1d9fdeb2-236d-4f14-b471-147611a63fdf") {
		t.Fatal("DBHandler.ValidateUUID() failed a valid UUID")
	}

	if dbhandler.ValidateUUID("1d9fdeb2-236d-4f14-b471-147611a63fdf/example.com") {
		t.Fatal("DBHandler.ValidateUUID() passed a workspace address as valid")
	}

	if dbhandler.ValidateUUID("Some garbage data") {
		t.Fatal("DBHandler.ValidateUUID() passed garbage data as a UUID")
	}
}
