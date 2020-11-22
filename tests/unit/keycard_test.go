package anselusd

import (
	"fmt"
	"testing"
	"time"

	"github.com/darkwyrm/anselusd/keycard"
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
		"Primary-Verification-Key:ED25519:)8id(gE02^S<{3H>9B;X4{DuYcb`%wo^mC&1lN88\r\n" +
		"Encryption-Key:CURVE25519:@b?cjpeY;<&y+LSOA&yUQ&ZIrp(JGt{W$*V>ATLG\r\n" +
		"Time-To-Live:14\r\n" +
		"Expires:20201002\r\n" +
		"Hash:BLAKE3-256:^zPiV;CKvLd2(uwpIzmyMotYFsKM=cgbL=nSI2LN\r\n" +
		"Organization-Signature:ED25519:6lXjej0C~!F&_`qnkPHrC`z8+>;#g*fNfjV@4ngGlp#xsr8}1rS2(NG" +
		")@ANTe`~05d)3*<q%pX`Oj0-t\r\n"

	entry := keycard.NewOrgEntry()
	err := entry.Set([]byte(sampleString))
	if err != nil {
		t.Fatal("Entry.Set() didn't work")
	}

	if entry.Signatures["Organization"] != "ED25519:6lXjej0C~!F&_`qnkPHrC`z8+>;#g*fNfjV@4ng"+
		"Glp#xsr8}1rS2(NG)@ANTe`~05d)3*<q%pX`Oj0-t" {
		t.Fatal("Entry.Set() didn't handle the signature correctly")
	}
}

func TestMakeByteString(t *testing.T) {
	sampleString :=
		"Name:Corbin Smith\r\n" +
			"User-ID:csmith\r\n" +
			"Timestamp:20200901T13\r\n" +
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
		"Timestamp:20200901T13\r\n" +
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
		"Contact-Request-Verification-Key": "ED25519:d0-oQb;{QxwnO{=!|^62+E=UYk2Y3mr2?XKScF4D",
		"Contact-Request-Encryption-Key":   "CURVE25519:j(IBzX*F%OZF;g77O8jrVjM1a`Y<6-ehe{S;{gph",
		"Public-Encryption-Key":            "CURVE25519:nSRso=K(WF{P+4x5S*5?Da-rseY-^>S8VN#v+)IN",
		"Time-To-Live":                     "30",
		"Expires":                          "20201002",
		"Timestamp":                        "20200901T13",

		// These junk signatures will end up being cleared when sign("Organization") is called
		"Organization-Signature": "1111111111",
		"User-Signature":         "2222222222"})

	var signingKey, orgSigningKey keycard.EncodedString

	err := signingKey.Set("ED25519:p;XXU0XF#UO^}vKbC-wS(#5W6=OEIFmR2z`rS1j+")
	if err != nil {
		t.Fatalf("TestVerify: signing key decoding failure: %s\n", err)
	}

	err = orgSigningKey.Set("ED25519:msvXw(nII<Qm6oBHc+92xwRI3>VFF-RcZ=7DEu3|")
	if err != nil {
		t.Fatalf("TestSign: signing key decoding failure: %s\n", err)
	}

	err = entry.Sign(orgSigningKey, "Organization")
	if err != nil {
		t.Fatalf("TestSign: signing failure: %s\n", err)
	}

	expectedSig := "ED25519:H^&a0>LUcw@3~iaE1iJ0=C2UIPTC-f_W)kdhraHoXqF**vDPPK>X_n&h7PhSK{~7A-5Q?0hnQw)mL*mV"
	if entry.Signatures["Organization"] != expectedSig {
		t.Errorf("TestSign: expected signature:  %s\n", expectedSig)
		t.Errorf("TestSign: actual signature:  %s\n", entry.Signatures["Organization"])
		t.Fatal("TestSign: entry did not yield the expected signature\n")
	}

	err = entry.GenerateHash("BLAKE2B-256")
	if err != nil {
		t.Fatalf("TestSign: hashing failure: %s\n", err)
	}
	expectedHash := "BLAKE2B-256:^v@qXI~g>dNA4zxr4e13U_Dq6Z_87Aj(s@pL|pf-"

	if entry.Hash != expectedHash {
		t.Errorf("TestSign: expected hash:  %s\n", expectedHash)
		t.Errorf("TestSign: actual hash:  %s\n", entry.Hash)
		t.Fatal("TestSign: entry did not yield the expected hash\n")
	}

	// User sign and verify
	err = entry.Sign(signingKey, "User")
	if err != nil {
		t.Fatalf("TestVerify: user signing failure: %s\n", err)
	}

	expectedSig = "ED25519:Lv5%nEe!ata-hYM`V*{c|2=2f-zcFHYP+KHOb9&*q%#OrnIWa?*|BmDl8Fq-8Ud-aG7b`<b3Pro9*N@*"
	if entry.Signatures["User"] != expectedSig {
		t.Errorf("TestSign: expected signature:  %s\n", expectedSig)
		t.Errorf("TestSign: actual signature:  %s\n", entry.Signatures["User"])
		t.Fatal("TestSign: entry did not yield the expected user signature\n")
	}
}

func TestVerify(t *testing.T) {
	var signingKey, orgSigningKey, verifyKey keycard.EncodedString

	err := signingKey.Set("ED25519:p;XXU0XF#UO^}vKbC-wS(#5W6=OEIFmR2z`rS1j+")
	if err != nil {
		t.Fatalf("TestVerify: signing key decoding failure: %s\n", err)
	}

	err = verifyKey.Set("ED25519:6|HBWrxMY6-?r&Sm)_^PLPerpqOj#b&x#N_#C3}p")
	if err != nil {
		t.Fatalf("TestVerify: verify key decoding failure: %s\n", err)
	}

	err = orgSigningKey.Set("ED25519:msvXw(nII<Qm6oBHc+92xwRI3>VFF-RcZ=7DEu3|")
	if err != nil {
		t.Fatalf("TestVerify: signing key decoding failure: %s\n", err)
	}

	entry := keycard.NewUserEntry()
	entry.SetFields(map[string]string{
		"Name":                             "Corbin Simons",
		"Workspace-ID":                     "4418bf6c-000b-4bb3-8111-316e72030468",
		"Domain":                           "example.com",
		"Contact-Request-Verification-Key": "ED25519:d0-oQb;{QxwnO{=!|^62+E=UYk2Y3mr2?XKScF4D",
		"Contact-Request-Encryption-Key":   "CURVE25519:j(IBzX*F%OZF;g77O8jrVjM1a`Y<6-ehe{S;{gph",
		"Public-Encryption-Key":            "CURVE25519:nSRso=K(WF{P+4x5S*5?Da-rseY-^>S8VN#v+)IN",
		"Time-To-Live":                     "30",
		"Expires":                          "20201002",
		"Timestamp":                        "20200901T13",

		// These junk signatures will end up being cleared when sign("Organization") is called
		"Organization-Signature": "1111111111",
		"User-Signature":         "2222222222"})

	// Organization sign and verify
	err = entry.Sign(orgSigningKey, "Organization")
	if err != nil {
		t.Fatalf("TestVerify: org signing failure: %s\n", err)
	}

	expectedSig := "ED25519:H^&a0>LUcw@3~iaE1iJ0=C2UIPTC-f_W)kdhraHoXqF**vDPPK>X_n&h7PhSK{~7A-5Q?0hnQw)mL*mV"
	if entry.Signatures["Organization"] != expectedSig {
		t.Errorf("TestVerify: expected signature:  %s\n", expectedSig)
		t.Errorf("TestVerify: actual signature:  %s\n", entry.Signatures["Organization"])
		t.Fatal("TestVerify: entry did not yield the expected org signature\n")
	}

	// Set up the hashes
	err = entry.GenerateHash("BLAKE2B-256")
	if err != nil {
		t.Fatalf("TestVerify: hashing failure: %s\n", err)
	}
	expectedHash := "BLAKE2B-256:^v@qXI~g>dNA4zxr4e13U_Dq6Z_87Aj(s@pL|pf-"

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

	expectedSig = "ED25519:Lv5%nEe!ata-hYM`V*{c|2=2f-zcFHYP+KHOb9&*q%#OrnIWa?*|BmDl8Fq-8Ud-aG7b`<b3Pro9*N@*"
	if entry.Signatures["User"] != expectedSig {
		t.Errorf("TestVerify: expected signature:  %s\n", expectedSig)
		t.Errorf("TestVerify: actual signature:  %s\n", entry.Signatures["User"])
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

func TestIsCompliantUser(t *testing.T) {
	var signingKey, orgSigningKey, verifyKey keycard.EncodedString

	err := signingKey.Set("ED25519:p;XXU0XF#UO^}vKbC-wS(#5W6=OEIFmR2z`rS1j+")
	if err != nil {
		t.Fatalf("TestIsCompliantUser: signing key decoding failure: %s\n", err)
	}

	err = verifyKey.Set("ED25519:6|HBWrxMY6-?r&Sm)_^PLPerpqOj#b&x#N_#C3}p")
	if err != nil {
		t.Fatalf("TestIsCompliantUser: verify key decoding failure: %s\n", err)
	}

	err = orgSigningKey.Set("ED25519:msvXw(nII<Qm6oBHc+92xwRI3>VFF-RcZ=7DEu3|")
	if err != nil {
		t.Fatalf("TestIsCompliantUser: signing key decoding failure: %s\n", err)
	}

	entry := keycard.NewUserEntry()
	entry.SetFields(map[string]string{
		"Name":                             "Corbin Simons",
		"Workspace-ID":                     "4418bf6c-000b-4bb3-8111-316e72030468",
		"Domain":                           "example.com",
		"Contact-Request-Verification-Key": "ED25519:d0-oQb;{QxwnO{=!|^62+E=UYk2Y3mr2?XKScF4D",
		"Contact-Request-Encryption-Key":   "CURVE25519:j(IBzX*F%OZF;g77O8jrVjM1a`Y<6-ehe{S;{gph",
		"Public-Encryption-Key":            "CURVE25519:nSRso=K(WF{P+4x5S*5?Da-rseY-^>S8VN#v+)IN",
		"Time-To-Live":                     "30",
		"Expires":                          "20201002",
		"Timestamp":                        "20200901T13"})

	if entry.IsCompliant() {
		t.Fatal("TestIsCompliantUser: compliance check passed a non-compliant entry\n")
	}

	// Organization sign and verify
	err = entry.Sign(orgSigningKey, "Organization")
	if err != nil {
		t.Fatalf("TestIsCompliantUser: org signing failure: %s\n", err)
	}

	expectedSig := "ED25519:H^&a0>LUcw@3~iaE1iJ0=C2UIPTC-f_W)kdhraHoXqF**vDPPK>X_n&h7PhSK{~7A-5Q?0hnQw)mL*mV"
	if entry.Signatures["Organization"] != expectedSig {
		t.Errorf("TestIsCompliantUser: expected signature:  %s\n", expectedSig)
		t.Errorf("TestIsCompliantUser: actual signature:  %s\n", entry.Signatures["Organization"])
		t.Fatal("TestIsCompliantUser: entry did not yield the expected org signature\n")
	}

	// Set up the hashes
	err = entry.GenerateHash("BLAKE2B-256")
	if err != nil {
		t.Fatalf("TestIsCompliantUser: hashing failure: %s\n", err)
	}
	expectedHash := "BLAKE2B-256:^v@qXI~g>dNA4zxr4e13U_Dq6Z_87Aj(s@pL|pf-"

	if entry.Hash != expectedHash {
		t.Errorf("TestIsCompliantUser: expected hash:  %s\n", expectedHash)
		t.Errorf("TestVTestIsCompliantUsererify: actual hash:  %s\n", entry.Hash)
		t.Fatal("TestIsCompliantUser: entry did not yield the expected hash\n")
	}

	// User sign and verify
	err = entry.Sign(signingKey, "User")
	if err != nil {
		t.Fatalf("TestIsCompliantUser: user signing failure: %s\n", err)
	}

	expectedSig = "ED25519:Lv5%nEe!ata-hYM`V*{c|2=2f-zcFHYP+KHOb9&*q%#OrnIWa?*|BmDl8Fq-8Ud-aG7b`<b3Pro9*N@*"
	if entry.Signatures["User"] != expectedSig {
		t.Errorf("TestIsCompliantUser: expected signature:  %s\n", expectedSig)
		t.Errorf("TestIsCompliantUser: actual signature:  %s\n", entry.Signatures["User"])
		t.Fatal("TestIsCompliantUser: entry did not yield the expected user signature\n")
	}

	var verified bool
	verified, err = entry.VerifySignature(verifyKey, "User")
	if err != nil {
		t.Fatalf("TestIsCompliantUser: user verify error: %s\n", err)
	}

	if !verified {
		t.Fatal("TestIsCompliantUser: user verify failure\n")
	}

	if !entry.IsCompliant() {
		t.Fatal("TestIsCompliantUser: compliance check failed a compliant user entry\n")
	}

}

func TestIsCompliantOrg(t *testing.T) {
	entry := keycard.NewOrgEntry()
	var orgSigningKey keycard.EncodedString

	err := orgSigningKey.Set("ED25519:msvXw(nII<Qm6oBHc+92xwRI3>VFF-RcZ=7DEu3|")
	if err != nil {
		t.Fatalf("TestIsCompliantOrg: org signing key decoding failure: %s\n", err)
	}

	entry.SetFields(map[string]string{
		"Name":                     "Acme, Inc.",
		"Contact-Admin":            "admin/acme.com",
		"Language":                 "en",
		"Primary-Verification-Key": "ED25519:)8id(gE02^S<{3H>9B;X4{DuYcb`%wo^mC&1lN88",
		"Encryption-Key":           "CURVE25519:@b?cjpeY;<&y+LSOA&yUQ&ZIrp(JGt{W$*V>ATLG",
		"Time-To-Live":             "14",
		"Expires":                  "20201002",
		"Timestamp":                "20200901T13"})

	if entry.IsCompliant() {
		t.Fatal("TestIsCompliantOrg: compliance check passed a non-compliant entry\n")
	}

	err = entry.GenerateHash("BLAKE2B-256")
	if err != nil {
		t.Fatalf("TestIsCompliantOrg: hashing failure: %s\n", err)
	}
	expectedHash := "BLAKE2B-256:T?YXdtc$aGOSSJ~+VW8mbK)uEMwS{K(ptGk{xP@N"

	if entry.Hash != expectedHash {
		t.Errorf("TestIsCompliantOrg: expected hash:  %s\n", expectedHash)
		t.Errorf("TestIsCompliantOrg: actual hash:  %s\n", entry.Hash)
		t.Fatal("TestIsCompliantOrg: entry did not yield the expected hash\n")
	}

	if entry.IsCompliant() {
		t.Fatal("TestIsCompliantOrg: compliance check passed a non-compliant entry\n")
	}

	// Organization sign and verify
	err = entry.Sign(orgSigningKey, "Organization")
	if err != nil {
		t.Fatalf("TestIsCompliantOrg: org signing failure: %s\n", err)
	}

	var verifyKey keycard.EncodedString
	err = verifyKey.Set("ED25519:)8id(gE02^S<{3H>9B;X4{DuYcb`%wo^mC&1lN88")
	if err != nil {
		t.Fatalf("TestIsCompliantOrg: verify key decoding failure: %s\n", err)
	}

	var verified bool
	verified, err = entry.VerifySignature(verifyKey, "Organization")
	if err != nil {
		t.Fatalf("TestIsCompliantOrg: user verify error: %s\n", err)
	}

	if !verified {
		t.Fatal("TestIsCompliantOrg: user verify failure\n")
	}

	if !entry.IsCompliant() {
		t.Fatal("TestIsCompliantOrg: compliance check failed a compliant org entry\n")
	}
}

func TestOrgChain(t *testing.T) {
	entry := keycard.NewOrgEntry()
	var orgSigningKey keycard.EncodedString

	err := orgSigningKey.Set("ED25519:msvXw(nII<Qm6oBHc+92xwRI3>VFF-RcZ=7DEu3|")
	if err != nil {
		t.Fatalf("TestIsCompliantOrg: org signing key decoding failure: %s\n", err)
	}

	entry.SetFields(map[string]string{
		"Name":                     "Acme, Inc.",
		"Contact-Admin":            "admin/acme.com",
		"Language":                 "en",
		"Primary-Verification-Key": "ED25519:)8id(gE02^S<{3H>9B;X4{DuYcb`%wo^mC&1lN88",
		"Encryption-Key":           "CURVE25519:@b?cjpeY;<&y+LSOA&yUQ&ZIrp(JGt{W$*V>ATLG",
		"Time-To-Live":             "14",
		"Expires":                  "20201002",
		"Timestamp":                "20200901T13"})

	err = entry.GenerateHash("BLAKE2B-256")
	if err != nil {
		t.Fatalf("TestOrgChain: hashing failure: %s\n", err)
	}
	expectedHash := "BLAKE2B-256:T?YXdtc$aGOSSJ~+VW8mbK)uEMwS{K(ptGk{xP@N"

	if entry.Hash != expectedHash {
		t.Errorf("TestOrgChain: expected hash:  %s\n", expectedHash)
		t.Errorf("TestOrgChain: actual hash:  %s\n", entry.Hash)
		t.Fatal("TestOrgChain: entry did not yield the expected hash\n")
	}

	// Organization sign and verify
	err = entry.Sign(orgSigningKey, "Organization")
	if err != nil {
		t.Fatalf("TestOrgChain: org signing failure: %s\n", err)
	}

	var verifyKey keycard.EncodedString
	err = verifyKey.Set("ED25519:)8id(gE02^S<{3H>9B;X4{DuYcb`%wo^mC&1lN88")
	if err != nil {
		t.Fatalf("TestOrgChain: verify key decoding failure: %s\n", err)
	}

	var verified bool
	verified, err = entry.VerifySignature(verifyKey, "Organization")
	if err != nil {
		t.Fatalf("TestOrgChain: user verify error: %s\n", err)
	}

	if !verified {
		t.Fatal("TestOrgChain: user verify failure\n")
	}

	if !entry.IsCompliant() {
		t.Fatal("TestOrgChain: compliance check failed a compliant org entry\n")
	}

	var newEntry *keycard.Entry
	var newKeys map[string]keycard.EncodedString
	newEntry, newKeys, err = entry.Chain(orgSigningKey, true)
	if err != nil {
		t.Fatalf("TestOrgChain: chain failure error: %s\n", err)
	}

	// Now that we have a new entry, it only has a valid custody signature. Add all the other
	// signatures needed to be compliant and then verify the whole thing.
	err = newEntry.GenerateHash("BLAKE2B-256")
	if err != nil {
		t.Fatalf("TestOrgChain: hashing failure: %s\n", err)
	}

	newpsKeyString := newKeys["Primary-Verification-Key.private"]
	err = newEntry.Sign(newpsKeyString, "Organization")
	if err != nil {
		t.Fatalf("TestIsCompliantOrg: org signing failure: %s\n", err)
	}

	if !entry.IsCompliant() {
		t.Fatal("TestOrgChain: compliance check failure on new entry\n")
	}

	verified, err = newEntry.VerifyChain(entry)
	if !verified {
		t.Fatalf("TestOrgChain: chain verify failure: %s\n", err)
	}
}

func TestUserChain(t *testing.T) {
	var signingKey, crSigningKey, orgSigningKey, verifyKey keycard.EncodedString

	err := signingKey.Set("ED25519:p;XXU0XF#UO^}vKbC-wS(#5W6=OEIFmR2z`rS1j+")
	if err != nil {
		t.Fatalf("TestUserChain: signing key decoding failure: %s\n", err)
	}

	err = crSigningKey.Set("ED25519:ip52{ps^jH)t$k-9bc_RzkegpIW?}FFe~BX&<V}9")
	if err != nil {
		t.Fatalf("TestUserChain: request signing key decoding failure: %s\n", err)
	}

	err = verifyKey.Set("ED25519:6|HBWrxMY6-?r&Sm)_^PLPerpqOj#b&x#N_#C3}p")
	if err != nil {
		t.Fatalf("TestUserChain: verify key decoding failure: %s\n", err)
	}

	err = orgSigningKey.Set("ED25519:msvXw(nII<Qm6oBHc+92xwRI3>VFF-RcZ=7DEu3|")
	if err != nil {
		t.Fatalf("TestUserChain: signing key decoding failure: %s\n", err)
	}

	entry := keycard.NewUserEntry()
	entry.SetFields(map[string]string{
		"Name":                             "Corbin Simons",
		"Workspace-ID":                     "4418bf6c-000b-4bb3-8111-316e72030468",
		"Domain":                           "example.com",
		"Contact-Request-Verification-Key": "ED25519:d0-oQb;{QxwnO{=!|^62+E=UYk2Y3mr2?XKScF4D",
		"Contact-Request-Encryption-Key":   "CURVE25519:j(IBzX*F%OZF;g77O8jrVjM1a`Y<6-ehe{S;{gph",
		"Public-Encryption-Key":            "CURVE25519:nSRso=K(WF{P+4x5S*5?Da-rseY-^>S8VN#v+)IN",
		"Time-To-Live":                     "30",
		"Expires":                          "20201002",
		"Timestamp":                        "20200901T13"})

	if entry.IsCompliant() {
		t.Fatal("TestUserChain: compliance check passed a non-compliant entry\n")
	}

	// Organization sign and verify
	err = entry.Sign(orgSigningKey, "Organization")
	if err != nil {
		t.Fatalf("TestUserChain: org signing failure: %s\n", err)
	}

	expectedSig := "ED25519:H^&a0>LUcw@3~iaE1iJ0=C2UIPTC-f_W)kdhraHoXqF**vDPPK>X_n&h7PhSK{~7A-5Q?0hnQw)mL*mV"
	if entry.Signatures["Organization"] != expectedSig {
		t.Errorf("TestUserChain: expected signature:  %s\n", expectedSig)
		t.Errorf("TestUserChain: actual signature:  %s\n", entry.Signatures["Organization"])
		t.Fatal("TestUserChain: entry did not yield the expected org signature\n")
	}

	// Set up the hashes
	err = entry.GenerateHash("BLAKE2B-256")
	if err != nil {
		t.Fatalf("TestUserChain: hashing failure: %s\n", err)
	}
	expectedHash := "BLAKE2B-256:^v@qXI~g>dNA4zxr4e13U_Dq6Z_87Aj(s@pL|pf-"

	if entry.Hash != expectedHash {
		t.Errorf("TestUserChain: expected hash:  %s\n", expectedHash)
		t.Errorf("TestUserChain: actual hash:  %s\n", entry.Hash)
		t.Fatal("TestUserChain: entry did not yield the expected hash\n")
	}

	// User sign and verify
	err = entry.Sign(signingKey, "User")
	if err != nil {
		t.Fatalf("TestUserChain: user signing failure: %s\n", err)
	}

	expectedSig = "ED25519:Lv5%nEe!ata-hYM`V*{c|2=2f-zcFHYP+KHOb9&*q%#OrnIWa?*|BmDl8Fq-8Ud-aG7b`<b3Pro9*N@*"
	if entry.Signatures["User"] != expectedSig {
		t.Errorf("TestUserChain: expected signature:  %s\n", expectedSig)
		t.Errorf("TestUserChain: actual signature:  %s\n", entry.Signatures["User"])
		t.Fatal("TestUserChain: entry did not yield the expected user signature\n")
	}

	var verified bool
	verified, err = entry.VerifySignature(verifyKey, "User")
	if err != nil {
		t.Fatalf("TestUserChain: user verify error: %s\n", err)
	}

	if !verified {
		t.Fatal("TestUserChain: user verify failure\n")
	}

	if !entry.IsCompliant() {
		t.Fatal("TestUserChain: compliance check failed a compliant user entry\n")
	}

	var newEntry *keycard.Entry
	var newKeys map[string]keycard.EncodedString
	newEntry, newKeys, err = entry.Chain(crSigningKey, true)
	if err != nil {
		t.Fatalf("TestUserChain: chain failure error: %s\n", err)
	}

	// Now that we have a new entry, it only has a valid custody signature. Add all the other
	// signatures needed to be compliant and then verify the whole thing.
	err = newEntry.Sign(orgSigningKey, "Organization")
	if err != nil {
		t.Fatalf("TestUserChain: org signing failure: %s\n", err)
	}
	err = newEntry.GenerateHash("BLAKE2B-256")
	if err != nil {
		t.Fatalf("TestUserChain: hashing failure: %s\n", err)
	}

	newpsKeyString := newKeys["Primary-Verification-Key.private"]
	err = newEntry.Sign(newpsKeyString, "User")
	if err != nil {
		t.Fatalf("TestUserChain: user signing failure: %s\n", err)
	}

	if !newEntry.IsCompliant() {
		t.Fatal("TestUserChain: compliance check failure on new entry\n")
	}

	verified, err = newEntry.VerifyChain(entry)
	if !verified {
		t.Fatalf("TestUserChain: chain verify failure: %s\n", err)
	}
}

func TestIsDataCompliantOrg(t *testing.T) {
	entry := keycard.NewOrgEntry()

	entry.SetFields(map[string]string{
		"Name":                     "Acme, Inc.",
		"Contact-Admin":            "54025843-bacc-40cc-a0e4-df48a099c2f3/acme.com",
		"Language":                 "en",
		"Primary-Verification-Key": "ED25519:)8id(gE02^S<{3H>9B;X4{DuYcb`%wo^mC&1lN88",
		"Encryption-Key":           "CURVE25519:@b?cjpeY;<&y+LSOA&yUQ&ZIrp(JGt{W$*V>ATLG",
		"Time-To-Live":             "14",
		"Expires":                  "20201002",
		"Timestamp":                "20200901T131313Z"})

	if !entry.IsDataCompliant() {
		t.Fatal("TestIsDataCompliantOrg: compliance failed a compliant entry\n")
	}

	// Now to test failures of each field. The extent of this testing wouldn't normally be
	// necessary, but this function validates data from outside. We *have* to be extra sure that
	// this data is good... especially when it will be permanently added to the database if it is
	// accepted.

	entry.SetField("Index", "-1")
	if entry.IsDataCompliant() {
		t.Fatal("TestIsDataCompliantOrg: IsDataCompliant passed an entry with a bad index\n")
	}
	entry.SetField("Index", "1")

	entry.SetField("Name", "")
	if entry.IsDataCompliant() {
		t.Fatal("TestIsDataCompliantOrg: IsDataCompliant passed an entry with an empty name\n")
	}
	entry.SetField("Name", "\t \t")
	if entry.IsDataCompliant() {
		t.Fatal("TestIsDataCompliantOrg: IsDataCompliant passed an entry with a whitespace name\n")
	}
	entry.SetField("Name", "Acme, Inc.")

	entry.SetField("Contact-Admin", "admin/example.com")
	if entry.IsDataCompliant() {
		t.Fatal("TestIsDataCompliantOrg: IsDataCompliant passed an entry with an Anselus address " +
			"for the admin contact\n")
	}
	entry.SetField("Contact-Admin", "54025843-bacc-40cc-a0e4-df48a099c2f3/acme.com")

	entry.SetField("Contact-Abuse", "abuse/example.com")
	if entry.IsDataCompliant() {
		t.Fatal("TestIsDataCompliantOrg: IsDataCompliant passed an entry with an Anselus address " +
			"for the abuse contact\n")
	}
	entry.SetField("Contact-Abuse", "54025843-bacc-40cc-a0e4-df48a099c2f3/acme.com")

	entry.SetField("Contact-Support", "support/example.com")
	if entry.IsDataCompliant() {
		t.Fatal("TestIsDataCompliantOrg: IsDataCompliant passed an entry with an Anselus address " +
			"for the support contact\n")
	}
	entry.SetField("Contact-Support", "54025843-bacc-40cc-a0e4-df48a099c2f3/acme.com")

	entry.SetField("Language", "en-us")
	if entry.IsDataCompliant() {
		t.Fatal("TestIsDataCompliantOrg: IsDataCompliant passed an entry with a bad language\n")
	}
	entry.SetField("Language", "de,es,FR")
	if !entry.IsDataCompliant() {
		t.Fatal("TestIsDataCompliantOrg: IsDataCompliant failed an entry with a passing language list\n")
	}

	entry.SetField("Primary-Verification-Key", "d0-oQb;{QxwnO{=!|^62+E=UYk2Y3mr2?XKScF4D")
	if entry.IsDataCompliant() {
		t.Fatal("TestIsDataCompliantOrg: IsDataCompliant passed an entry with a bad key\n")
	}
	entry.SetField("Primary-Verification-Key", "ED25519:123456789:123456789")
	if entry.IsDataCompliant() {
		t.Fatal("TestIsDataCompliantOrg: IsDataCompliant passed an entry with a bad key\n")
	}
	entry.SetField("Primary-Verification-Key", "ED25519:d0-oQb;{QxwnO{=!|^62+E=UYk2Y3mr2?XKScF4D")

	entry.SetField("Secondary-Verification-Key", "d0-oQb;{QxwnO{=!|^62+E=UYk2Y3mr2?XKScF4D")
	if entry.IsDataCompliant() {
		t.Fatal("TestIsDataCompliantOrg: IsDataCompliant passed an entry with a bad key\n")
	}
	entry.SetField("Secondary-Verification-Key", "ED25519:123456789:123456789")
	if entry.IsDataCompliant() {
		t.Fatal("TestIsDataCompliantOrg: IsDataCompliant passed an entry with a bad key\n")
	}
	entry.SetField("Secondary-Verification-Key", "ED25519:d0-oQb;{QxwnO{=!|^62+E=UYk2Y3mr2?XKScF4D")

	entry.SetField("Encryption-Key", "d0-oQb;{QxwnO{=!|^62+E=UYk2Y3mr2?XKScF4D")
	if entry.IsDataCompliant() {
		t.Fatal("TestIsDataCompliantOrg: IsDataCompliant passed an entry with a bad key\n")
	}
	entry.SetField("Encryption-Key", "ED25519:123456789:123456789")
	if entry.IsDataCompliant() {
		t.Fatal("TestIsDataCompliantOrg: IsDataCompliant passed an entry with a bad key\n")
	}
	entry.SetField("Encryption-Key", "ED25519:d0-oQb;{QxwnO{=!|^62+E=UYk2Y3mr2?XKScF4D")

	entry.SetField("Time-To-Live", "0")
	if entry.IsDataCompliant() {
		t.Fatal("TestIsDataCompliantOrg: IsDataCompliant passed an entry with a bad TTL\n")
	}
	entry.SetField("Time-To-Live", "60")
	if entry.IsDataCompliant() {
		t.Fatal("TestIsDataCompliantOrg: IsDataCompliant passed an entry with a bad TTL\n")
	}
	entry.SetField("Time-To-Live", "sdf'pomwerASDFOAQEtmlde123,l.")
	if entry.IsDataCompliant() {
		t.Fatal("TestIsDataCompliantOrg: IsDataCompliant passed an entry with a bad TTL\n")
	}
	entry.SetField("Time-To-Live", "7")

	tempStr := entry.Fields["Expires"]
	entry.SetField("Expires", "12345678")
	if entry.IsDataCompliant() {
		t.Fatal("TestIsDataCompliantOrg: IsDataCompliant passed an entry with a bad expiration date\n")
	}
	entry.SetField("Expires", "99999999")
	if entry.IsDataCompliant() {
		t.Fatal("TestIsDataCompliantOrg: IsDataCompliant passed an entry with a bad expiration date\n")
	}
	entry.SetField("Expires", tempStr)

	entry.SetField("Timestamp", "12345678 121212")
	if entry.IsDataCompliant() {
		t.Fatal("TestIsDataCompliantOrg: IsDataCompliant passed an entry with a bad " +
			"format timestamp\n")
	}
	entry.SetField("Timestamp", "12345678T121212Z")
	if entry.IsDataCompliant() {
		t.Fatal("TestIsDataCompliantOrg: IsDataCompliant passed an entry with a too-old timestamp\n")
	}
	entry.SetField("Timestamp", "20200901T131313Z")
}

func TestIsDataCompliantUser(t *testing.T) {
	// TODO: Implement TestIsDataCompliantUser
}

func TestIsExpired(t *testing.T) {
	entry := keycard.NewOrgEntry()

	// NewOrgEntry always creates an entry with a valid expiration date
	isExpired, err := entry.IsExpired()
	if err != nil {
		t.Fatal("TestIsDataCompliantOrg: IsExpired returned an error\n")
	}
	if isExpired {
		t.Fatal("TestIsDataCompliantOrg: IsExpired failed a passing expiration date\n")
	}

	entry.SetFields(map[string]string{
		"Name":                     "Acme, Inc.",
		"Contact-Admin":            "54025843-bacc-40cc-a0e4-df48a099c2f3/acme.com",
		"Language":                 "en",
		"Primary-Verification-Key": "ED25519:)8id(gE02^S<{3H>9B;X4{DuYcb`%wo^mC&1lN88",
		"Encryption-Key":           "CURVE25519:@b?cjpeY;<&y+LSOA&yUQ&ZIrp(JGt{W$*V>ATLG",
		"Time-To-Live":             "14",
		"Expires":                  "20201002",
		"Timestamp":                "20200901T131313Z"})

	isExpired, err = entry.IsExpired()
	if err != nil {
		t.Fatal("TestIsDataCompliantOrg: IsExpired returned an error\n")
	}
	if !isExpired {
		t.Fatal("TestIsDataCompliantOrg: IsExpired passed a failing expiration date\n")
	}
}

func TestIsTimestampValid(t *testing.T) {
	entry := keycard.NewOrgEntry()

	// NewOrgEntry always creates an entry with a valid timestamp
	err := entry.IsTimestampValid()
	if err != nil {
		t.Fatal("TestIsTimestampValid: IsTimestampValid failed a passing timestamp\n")
	}

	entry.SetFields(map[string]string{
		"Name":                     "Acme, Inc.",
		"Contact-Admin":            "54025843-bacc-40cc-a0e4-df48a099c2f3/acme.com",
		"Language":                 "en",
		"Primary-Verification-Key": "ED25519:)8id(gE02^S<{3H>9B;X4{DuYcb`%wo^mC&1lN88",
		"Encryption-Key":           "CURVE25519:@b?cjpeY;<&y+LSOA&yUQ&ZIrp(JGt{W$*V>ATLG",
		"Time-To-Live":             "14",
		"Expires":                  "20201002",
		"Timestamp":                "20200901 131313"})

	err = entry.IsTimestampValid()
	if err == nil {
		t.Fatal("TestIsTimestampValid: IsTimestampValid passed a failing timestamp\n")
	}
}
