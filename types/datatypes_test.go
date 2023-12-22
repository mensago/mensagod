package types

import (
	"strings"
	"testing"
)

func TestToDomain(t *testing.T) {
	testname := "TestToDomain"

	for _, val := range []string{
		"foo-bar.baz.com",
		"FOO.bar.com ",
	} {
		if _, err := ToDomain(val); err != nil {
			t.Fatalf("%s: test failure on valid domain %s", testname, val)
		}
	}

	for _, val := range []string{
		"a bad-id.com",
		"also_bad.org",
	} {
		if _, err := ToDomain(val); err == nil {
			t.Fatalf("%s: test failure on invalid domain %s", testname, val)
		}
	}
}

func TestToMAddress(t *testing.T) {
	testname := "TestToMAddress"

	for _, val := range []string{"csimons/example.com"} {
		if _, err := ToMAddress(val); err != nil {
			t.Fatalf("%s: test failure on valid MAddress %s", testname, val)
		}
	}

	for _, val := range []string{
		"has spaces/example.com",
		"has_a_\"/example.com",
		"\\not_allowed/example.com",
		"/example.com",
		"5a56260b-aa5c-4013-9217-a78f094432c3/example.com/example.com",
		"5a56260b-aa5c-4013-9217-a78f094432c3",
		(strings.Repeat("a", 65)) + "/example.com",
	} {
		if _, err := ToMAddress(val); err == nil {
			t.Fatalf("%s: test failure on invalid MAddress '%s'", testname, val)
		}
	}
}

func TestToRandomID(t *testing.T) {
	testname := "TestToRandomID"

	if _, err := ToRandomID("981ad932-8fb9-47c5-8f03-56c8f9f5dc2f"); err != nil {
		t.Fatalf("%s: test failure on valid RandomID", testname)
	}

	for _, val := range []string{"csimons", "11111111111111111111111111111111"} {
		if _, err := ToRandomID(val); err == nil {
			t.Fatalf("%s: test failure on invalid RandomID %s", testname, val)
		}
	}
}

func TestToUserID(t *testing.T) {
	testname := "TestToUserID"

	for _, val := range []string{
		"GoodID",
		"alsogoooood",
		"3_Simons_and_a_fuzzy",
		"11111111-1111-1111-1111-111111111111",
		strings.Repeat("a", 64),
	} {
		if _, err := ToUserID(val); err != nil {
			t.Fatalf("%s: test failure on valid UserID %s", testname, val)
		}
	}

	for _, val := range []string{
		"has spaces",
		"has_a_\"",
		"🐧",
		"ಅಎಇ",
		"consecutive..dots",
		"hashtag-invalid#2",
		"also/bad",
		strings.Repeat("a", 65),
	} {
		if _, err := ToUserID(val); err == nil {
			t.Fatalf("%s: test failure on invalid UserID %s", testname, val)
		}
	}
}