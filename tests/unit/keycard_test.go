package server

import (
	"fmt"
	"testing"

	"github.com/darkwyrm/server/keycard"
)

func TestSetField(t *testing.T) {

	entry := keycard.NewUserEntry()
	err := entry.SetField("Name", "Corbin Smith")
	if err != nil || entry.Fields["Name"] != "Corbin Smith" {
		t.Fatal("Entry.SetField() didn't work")
	}
}

func TestSetFields(t *testing.T) {
	entry := keycard.NewOrgEntry()
	entry.SetFields(map[string]string{
		"Name":               "Example, Inc.",
		"Contact-Admin":      "admin/example.com",
		"noncompliant-field": "foobar2000"})
}

func TestSet(t *testing.T) {
	sampleString := "Name:Acme, Inc.\r\n" +
		"Contact-Admin:admin/acme.com\r\n" +
		"Language:en\r\n" +
		"Primary-Verification-Key:ED25519:&JEq)5Ktu@jfM+Sa@+1GU6E&Ct2*<2ZYXh#l0FxP\r\n" +
		"Encryption-Key:CURVE25519:^fI7bdC(IEwC#(nG8Em-;nx98TcH<TnfvajjjDV@\r\n" +
		"Time-To-Live:14\r\n" +
		"Expires:730\r\n" +
		"Organization-Signature:x3)dYq@S0rd1Rfbie*J7kF{fkxQ=J=A)OoO1WGx97o-utWtfbwyn-$(js" +
		"_n^d6uTZY7p{gd60=rPZ|;m\r\n"

	entry := keycard.NewOrgEntry()
	err := entry.Set([]byte(sampleString))
	if err != nil {
		t.Fatal("Entry.Set() didn't work")
	}
	fmt.Println(entry.Signatures["Organization"])
	if entry.Signatures["Organization"] != "x3)dYq@S0rd1Rfbie*J7kF{fkxQ=J=A)OoO1WGx"+
		"97o-utWtfbwyn-$(js_n^d6uTZY7p{gd60=rPZ|;m" {
		t.Fatal("Entry.Set() didn't handle the signature correctly")
	}
}
