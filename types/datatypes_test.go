package types

import "testing"

func TestToRandomID(t *testing.T) {
	testname := "TestRandomID"

	if _, err := ToRandomID("981ad932-8fb9-47c5-8f03-56c8f9f5dc2f"); err != nil {
		t.Fatalf("%s: failure on valid RandomID", testname)
	}

	for _, val := range []string{"csimons", "11111111111111111111111111111111"} {
		if _, err := ToRandomID("csimons"); err == nil {
			t.Fatalf("%s: failure on invalid RandomID %s", testname, val)
		}
	}
}
