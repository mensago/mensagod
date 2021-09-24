package mensagod

import (
	"testing"

	ezn "github.com/darkwyrm/goeznacl"
	"github.com/darkwyrm/mensagod/keycard"
)

func TestEntrySize(t *testing.T) {
	var card keycard.Keycard

	var signingKey, crSigningKey, orgSigningKey, verifyKey ezn.CryptoString

	err := signingKey.Set("ED25519:p;XXU0XF#UO^}vKbC-wS(#5W6=OEIFmR2z`rS1j+")
	if err != nil {
		t.Fatalf("BenchmarkEntrySize: signing key decoding failure: %s\n", err)
	}

	err = crSigningKey.Set("ED25519:ip52{ps^jH)t$k-9bc_RzkegpIW?}FFe~BX&<V}9")
	if err != nil {
		t.Fatalf("BenchmarkEntrySize: request signing key decoding failure: %s\n", err)
	}

	err = verifyKey.Set("ED25519:6|HBWrxMY6-?r&Sm)_^PLPerpqOj#b&x#N_#C3}p")
	if err != nil {
		t.Fatalf("BenchmarkEntrySize: verify key decoding failure: %s\n", err)
	}

	err = orgSigningKey.Set("ED25519:msvXw(nII<Qm6oBHc+92xwRI3>VFF-RcZ=7DEu3|")
	if err != nil {
		t.Fatalf("BenchmarkEntrySize: signing key decoding failure: %s\n", err)
	}

	entry := keycard.NewUserEntry()
	entry.SetFields(map[string]string{
		"Name":                             "Corbin Simons",
		"Workspace-ID":                     "4418bf6c-000b-4bb3-8111-316e72030468",
		"Domain":                           "example.com",
		"Contact-Request-Verification-Key": "ED25519:d0-oQb;{QxwnO{=!|^62+E=UYk2Y3mr2?XKScF4D",
		"Contact-Request-Encryption-Key":   "CURVE25519:j(IBzX*F%OZF;g77O8jrVjM1a`Y<6-ehe{S;{gph",
		"Encryption-Key":                   "CURVE25519:nSRso=K(WF{P+4x5S*5?Da-rseY-^>S8VN#v+)IN",
		"Verification-Key":                 "ED25519:k^GNIJbl3p@N=j8diO-wkNLuLcNF6#JF=@|a}wFE",
		"Time-To-Live":                     "30",
		"Expires":                          "20201002"})

	if entry.IsCompliant() {
		t.Fatal("BenchmarkEntrySize: compliance check passed a non-compliant entry\n")
	}

	// Signatures and hashes
	err = entry.Sign(orgSigningKey, "Organization")
	if err != nil {
		t.Fatalf("BenchmarkEntrySize: org signing failure: %s\n", err)
	}

	err = entry.GenerateHash("BLAKE2B-256")
	if err != nil {
		t.Fatalf("BenchmarkEntrySize: hashing failure: %s\n", err)
	}

	err = entry.Sign(signingKey, "User")
	if err != nil {
		t.Fatalf("BenchmarkEntrySize: user signing failure: %s\n", err)
	}

	var verified bool
	verified, err = entry.VerifySignature(verifyKey, "User")
	if err != nil {
		t.Fatalf("BenchmarkEntrySize: user verify error: %s\n", err)
	}

	if !verified {
		t.Fatal("BenchmarkEntrySize: user verify failure\n")
	}

	if !entry.IsCompliant() {
		t.Fatal("BenchmarkEntrySize: compliance check failed a compliant user entry\n")
	}

	card.Type = "User"
	card.Entries = append(card.Entries, *entry)

	var maxEntrySize int
	for index := 0; index < 10; index++ {
		var newEntry *keycard.Entry
		var newKeys map[string]ezn.CryptoString
		newEntry, newKeys, err = entry.Chain(crSigningKey, true)
		if err != nil {
			t.Fatalf("BenchmarkEntrySize: chain failure error: %s\n", err)
		}

		// Now that we have a new entry, it only has a valid custody signature. Add all the other
		// signatures needed to be compliant and then verify the whole thing.
		err = newEntry.Sign(orgSigningKey, "Organization")
		if err != nil {
			t.Fatalf("BenchmarkEntrySize: org signing failure: %s\n", err)
		}
		err = newEntry.GenerateHash("BLAKE2B-256")
		if err != nil {
			t.Fatalf("BenchmarkEntrySize: hashing failure: %s\n", err)
		}

		newpsKeyString := newKeys["Verification-Key.private"]
		err = newEntry.Sign(newpsKeyString, "User")
		if err != nil {
			t.Fatalf("BenchmarkEntrySize: user signing failure: %s\n", err)
		}

		if !newEntry.IsCompliant() {
			t.Fatal("BenchmarkEntrySize: compliance check failure on new entry\n")
		}

		verified, err = newEntry.VerifyChain(entry)
		if !verified {
			t.Fatalf("BenchmarkEntrySize: chain verify failure: %s\n", err)
		}

		entryLength := len(newEntry.MakeByteString(-1))
		if entryLength > maxEntrySize {
			maxEntrySize = entryLength
		}
		card.Entries = append(card.Entries, *newEntry)
	}

}

func BenchmarkBLAKE2_256(t *testing.B) {
	// Check the efficiency of the different hashing algorithms on a keycard
	entry := keycard.NewUserEntry()
	entry.SetFields(map[string]string{
		"Name":                             "Corbin Simons",
		"Workspace-ID":                     "4418bf6c-000b-4bb3-8111-316e72030468",
		"Domain":                           "example.com",
		"Contact-Request-Verification-Key": "ED25519:d0-oQb;{QxwnO{=!|^62+E=UYk2Y3mr2?XKScF4D",
		"Contact-Request-Encryption-Key":   "CURVE25519:j(IBzX*F%OZF;g77O8jrVjM1a`Y<6-ehe{S;{gph",
		"Encryption-Key":                   "CURVE25519:nSRso=K(WF{P+4x5S*5?Da-rseY-^>S8VN#v+)IN",
		"Time-To-Live":                     "30",
		"Expires":                          "20201002"})

	for i := 0; i < 25000; i++ {
		entry.GenerateHash("BLAKE2B-256")
	}
}

func BenchmarkBLAKE3_256(t *testing.B) {
	entry := keycard.NewUserEntry()
	entry.SetFields(map[string]string{
		"Name":                             "Corbin Simons",
		"Workspace-ID":                     "4418bf6c-000b-4bb3-8111-316e72030468",
		"Domain":                           "example.com",
		"Contact-Request-Verification-Key": "ED25519:d0-oQb;{QxwnO{=!|^62+E=UYk2Y3mr2?XKScF4D",
		"Contact-Request-Encryption-Key":   "CURVE25519:j(IBzX*F%OZF;g77O8jrVjM1a`Y<6-ehe{S;{gph",
		"Encryption-Key":                   "CURVE25519:nSRso=K(WF{P+4x5S*5?Da-rseY-^>S8VN#v+)IN",
		"Time-To-Live":                     "30",
		"Expires":                          "20201002"})

	for i := 0; i < 25000; i++ {
		entry.GenerateHash("BLAKE3-256")
	}
}

func BenchmarkSHA_256(t *testing.B) {
	// Check the efficiency of the different hashing algorithms on a keycard
	entry := keycard.NewUserEntry()
	entry.SetFields(map[string]string{
		"Name":                             "Corbin Simons",
		"Workspace-ID":                     "4418bf6c-000b-4bb3-8111-316e72030468",
		"Domain":                           "example.com",
		"Contact-Request-Verification-Key": "ED25519:d0-oQb;{QxwnO{=!|^62+E=UYk2Y3mr2?XKScF4D",
		"Contact-Request-Encryption-Key":   "CURVE25519:j(IBzX*F%OZF;g77O8jrVjM1a`Y<6-ehe{S;{gph",
		"Encryption-Key":                   "CURVE25519:nSRso=K(WF{P+4x5S*5?Da-rseY-^>S8VN#v+)IN",
		"Time-To-Live":                     "30",
		"Expires":                          "20201002"})

	for i := 0; i < 25000; i++ {
		entry.GenerateHash("SHA-256")
	}
}

func BenchmarkSHA3_256(t *testing.B) {
	// Check the efficiency of the different hashing algorithms on a keycard
	entry := keycard.NewUserEntry()
	entry.SetFields(map[string]string{
		"Name":                             "Corbin Simons",
		"Workspace-ID":                     "4418bf6c-000b-4bb3-8111-316e72030468",
		"Domain":                           "example.com",
		"Contact-Request-Verification-Key": "ED25519:d0-oQb;{QxwnO{=!|^62+E=UYk2Y3mr2?XKScF4D",
		"Contact-Request-Encryption-Key":   "CURVE25519:j(IBzX*F%OZF;g77O8jrVjM1a`Y<6-ehe{S;{gph",
		"Encryption-Key":                   "CURVE25519:nSRso=K(WF{P+4x5S*5?Da-rseY-^>S8VN#v+)IN",
		"Time-To-Live":                     "30",
		"Expires":                          "20201002"})

	for i := 0; i < 25000; i++ {
		entry.GenerateHash("SHA3-256")
	}
}
