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

func TestGetMensagoAddressType(t *testing.T) {

	if dbhandler.GetMensagoAddressType("csmith/example.com") != 2 {
		t.Fatal("DBHandler.GetMensagoAddressType() failed a valid address")
	}

	if dbhandler.GetMensagoAddressType("1d9fdeb2-236d-4f14-b471-147611a63fdf/example.com") != 1 {
		t.Fatal("DBHandler.GetMensagoAddressType() failed a workspace address")
	}

	if dbhandler.GetMensagoAddressType("1d9fdeb2-236d-4f14-b471-147611a63fdf") != 0 {
		t.Fatal("DBHandler.GetMensagoAddressType() passed a workspace ID as a valid " +
			"Mensago address")
	}

	if dbhandler.GetMensagoAddressType("Some garbage data") != 0 {
		t.Fatal("DBHandler.GetMensagoAddressType() passed garbage data")
	}

	if dbhandler.GetMensagoAddressType("Corbin Smith/example.com") != 0 {
		t.Fatal("DBHandler.GetMensagoAddressType() passed an Mensago address with " +
			"invalid characters")
	}

	if dbhandler.GetMensagoAddressType("Corbin \"Stretch\" Smith/example.com") != 0 {
		t.Fatal("DBHandler.GetMensagoAddressType() passed an Mensago address with " +
			"invalid characters")
	}
}
