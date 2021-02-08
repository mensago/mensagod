package fshandler

import "testing"

func TestValidateAnselusPath(t *testing.T) {

	testPath1 := "/ 3e782960-a762-4def-8038-a1d0a3cd951d e5c2f479-b9db-4475-8152-e76605e731fc"
	if ValidateAnselusPath(testPath1) != true {
		t.Fatal("ValidateAnselusPath didn't validate a valid path")
	}

	testPath2 := "3e782960-a762-4def-8038-a1d0a3cd951d e5c2f479-b9db-4475-8152-e76605e731fc"
	if ValidateAnselusPath(testPath2) != false {
		t.Fatal("ValidateAnselusPath subtest #2 validated a bad path")
	}

	testPath3 := " / 3e782960-a762-4def-8038-a1d0a3cd951d e5c2f479-b9db-4475-8152-e76605e731fc"
	if ValidateAnselusPath(testPath3) != false {
		t.Fatal("ValidateAnselusPath subtest #3 validated a bad path")
	}
}
