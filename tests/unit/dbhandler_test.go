package anselusd

import (
	"testing"

	"github.com/darkwyrm/anselusd/dbhandler"
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

func TestGetAnselusAddressType(t *testing.T) {

	if dbhandler.GetAnselusAddressType("csmith/example.com") != 2 {
		t.Fatal("DBHandler.GetAnselusAddressType() failed a valid address")
	}

	if dbhandler.GetAnselusAddressType("1d9fdeb2-236d-4f14-b471-147611a63fdf/example.com") != 1 {
		t.Fatal("DBHandler.GetAnselusAddressType() failed a workspace address")
	}

	if dbhandler.GetAnselusAddressType("1d9fdeb2-236d-4f14-b471-147611a63fdf") != 0 {
		t.Fatal("DBHandler.GetAnselusAddressType() passed a workspace ID as a valid " +
			"Anselus address")
	}

	if dbhandler.GetAnselusAddressType("Some garbage data") != 0 {
		t.Fatal("DBHandler.GetAnselusAddressType() passed garbage data")
	}

	if dbhandler.GetAnselusAddressType("Corbin Smith/example.com") != 0 {
		t.Fatal("DBHandler.GetAnselusAddressType() passed an Anselus address with " +
			"invalid characters")
	}

	if dbhandler.GetAnselusAddressType("Corbin \"Stretch\" Smith/example.com") != 0 {
		t.Fatal("DBHandler.GetAnselusAddressType() passed an Anselus address with " +
			"invalid characters")
	}
}

func TestResolveAddress(t *testing.T) {
	// TODO: Implement
}
