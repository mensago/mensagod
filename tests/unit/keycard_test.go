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

func TestVerify(t *testing.T) {
	var signingKey, orgSigningKey, verifyKey keycard.AlgoString

	err := signingKey.Set("ED25519:p;XXU0XF#UO^}vKbC-wS(#5W6=OEIFmR2z`rS1j+")
	if err != nil {
		t.Fatalf("TestSign: signing key decoding failure: %s\n", err)
	}

	err = orgSigningKey.Set("ED25519:msvXw(nII<Qm6oBHc+92xwRI3>VFF-RcZ=7DEu3|")
	if err != nil {
		t.Fatalf("TestSign: signing key decoding failure: %s\n", err)
	}

	err = verifyKey.Set("ED25519:6|HBWrxMY6-?r&Sm)_^PLPerpqOj#b&x#N_#C3}p")
	if err != nil {
		t.Fatalf("TestSign: verify key decoding failure: %s\n", err)
	}

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

	// Organization sign and verify
	err = entry.Sign(orgSigningKey, "Organization")
	if err != nil {
		t.Fatalf("TestVerify: org signing failure: %s\n", err)
	}

	expectedSig := "ED25519:stdU*<>f~?m(LhhS1z#sY!s-N`$-evY@j)@KP)=A>X0Vd{*$IH*SWyB$zH;Wk_eC%DA3%f31fQ;?Xrvw"
	if entry.Signatures["Organization"] != expectedSig {
		t.Errorf("TestVerify: expected signature:  %s\n", expectedSig)
		t.Errorf("TestVerify: actual signature:  %s\n", entry.Signatures["Organization"])
		t.Fatal("TestVerify: entry did not yield the expected org signature\n")
	}

	// Set up the hashes
	entry.PrevHash = "1234567890"
	err = entry.GenerateHash("BLAKE3-256")
	if err != nil {
		t.Fatalf("TestVerify: hashing failure: %s\n", err)
	}
	expectedHash := "BLAKE3-256:d0;tNM(8Q1dRN|}7`g8dH#fxYK(WHKiFX`bcHLkUG3+BMFmNht6Qg9yQ*;VAE!Qd" +
		"CgM%D>bTXG$8qm`7!z2_Y;R=ox&{Z57ryXRf<Br+Dw$^D^@4+I$mpHhTu6>o2-xd$s<dT71)v`QDj6J1s?MbLQm" +
		"N}&HHxVWHsOjNC;x1W<_gmHQDJk-!(%{MdC(!j0=<P+(HtavCqQ{LiQRNK*Op9n^U~HntVN>#BeKrgt<O6Ui+f`" +
		"d$_~eUW*E}&wYcW#ERZ(E}geS}XngGZ!-L!uvmRuLE|8ds{0L9r1<x$Y3UJsQQDHo{}L2Ji~VfebS_Uv?p"

	if entry.Hash != expectedHash {
		t.Errorf("TestVerify: expected hash:  %s\n", expectedHash)
		t.Errorf("TestVerify: actual hash:  %s\n", entry.Hash)
		t.Fatal("TestVerify: entry did not yield the expected hash\n")
	}

	// User sign and verify
	err = entry.Sign(signingKey, "User")
	if err != nil {
		t.Fatalf("TestVerify: user signing failure: %s\n", err)
	}

	expectedSig = "ED25519:n23~;I*EX`aX00YRu}Q}J=;4~0{Bt@WtE--Ve>zT!gf5E(+IH8Crv~TRRZZ$wFuTOw+Hj-7+`HcVozfR"
	if entry.Signatures["User"] != expectedSig {
		t.Errorf("TestVerify: expected signature:  %s\n", expectedSig)
		t.Errorf("TestVerify: actual signature:  %s\n", entry.Signatures["Organization"])
		t.Fatal("TestVerify: entry did not yield the expected user signature\n")
	}

	var verified bool
	verified, err = entry.VerifySignature(verifyKey, "User")
	if err != nil {
		t.Fatalf("TestVerify: user verify error: %s\n", err)
	}

	if !verified {
		t.Fatal("TestVerify: user verify failure\n")
	}
}
