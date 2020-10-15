package server

import (
	"fmt"
	"testing"
	"time"

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

	if entry.Signatures["Organization"] != "x3)dYq@S0rd1Rfbie*J7kF{fkxQ=J=A)OoO1WGx"+
		"97o-utWtfbwyn-$(js_n^d6uTZY7p{gd60=rPZ|;m" {
		t.Fatal("Entry.Set() didn't handle the signature correctly")
	}
}

func TestMakeByteString(t *testing.T) {
	sampleString :=
		"Name:Corbin Smith\r\n" +
			"User-ID:csmith\r\n" +
			"Custody-Signature:0000000000\r\n" +
			"Organization-Signature:2222222222\r\n" +
			"User-Signature:1111111111\r\n"

	entry := keycard.NewUserEntry()
	err := entry.Set([]byte(sampleString))
	if err != nil {
		t.Fatal("Entry.Set() didn't work")
	}

	actualOut := string(entry.MakeByteString(-1))
	expectedOut := "Type:User\r\n" +
		"Index:1\r\n" +
		"Name:Corbin Smith\r\n" +
		"User-ID:csmith\r\n" +
		"Time-To-Live:30\r\n" +
		"Custody-Signature:0000000000\r\n" +
		"Organization-Signature:2222222222\r\n" +
		"User-Signature:1111111111\r\n"
	if actualOut != expectedOut {
		fmt.Println("Actual: " + actualOut)
		fmt.Println("Expected: " + expectedOut)

		t.Fatal("Entry.MakeByteString() didn't match expectations")
	}
}

func TestSetExpiration(t *testing.T) {
	entry := keycard.NewUserEntry()
	entry.SetExpiration(7)
	expiration := time.Now().AddDate(0, 0, 7).Format("%Y%m%d")
	if entry.Fields["Expiration"] != expiration {
		t.Fatal("expiration calculations failed")
	}
}

func TestSign(t *testing.T) {
	entry := keycard.NewUserEntry()
	entry.SetFields(map[string]string{
		"Name":                             "Corbin Simons",
		"Workspace-ID":                     "4418bf6c-000b-4bb3-8111-316e72030468",
		"Domain":                           "example.com",
		"Contact-Request-Verification-Key": "ED25519:7dfD==!Jmt4cDtQDBxYa7(dV|N$}8mYwe$=RZuW|",
		"Contact-Request-Encryption-Key":   "CURVE25519:yBZ0{1fE9{2<b~#i^R+JT-yh-y5M(Wyw_)}_SZOn",
		"Public-Encryption-Key":            "CURVE25519:_`UC|vltn_%P5}~vwV^)oY){#uvQSSy(dOD_l(yE",
		"Expires":                          "20201002",

		// These junk signatures will end up being cleared when sign("Organization") is called
		"Organization-Signature": "1111111111",
		"User-Signature":         "2222222222"})

	var signingKey keycard.AlgoString
	err := signingKey.Set("ED25519:p;XXU0XF#UO^}vKbC-wS(#5W6=OEIFmR2z`rS1j+")
	if err != nil {
		t.Fatalf("TestSign: signing key decoding failure: %s\n", err)
	}

	err = entry.Sign(signingKey, "Organization")
	if err != nil {
		t.Fatalf("TestSign: signing failure: %s\n", err)
	}

	err = entry.GenerateHash("BLAKE3-256")
	if err != nil {
		t.Fatalf("TestSign: hashing failure: %s\n", err)
	}

	expectedSig := "ED25519:7HkLW3-_%#`F{n&Mv%p1GZ?nerY^*S_bUVdt}EH;1J3@&ADgxLdg1t{IdXp#-t1qW1?cW;u<8Yi9KnMN"
	if entry.Signatures["Organization"] != expectedSig {
		t.Errorf("TestSign: expected signature:  %s\n", expectedSig)
		t.Errorf("TestSign: actual signature:  %s\n", entry.Signatures["Organization"])
		t.Fatal("TestSign: entry did not yield the expected signature\n")
	}
}
