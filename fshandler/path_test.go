package fshandler

import (
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

func TestValidateMensagoPath(t *testing.T) {

	goodTestPaths := []string{
		"/ 3e782960-a762-4def-8038-a1d0a3cd951d e5c2f479-b9db-4475-8152-e76605e731fc",
		"/ wsp 3e782960-a762-4def-8038-a1d0a3cd951d e5c2f479-b9db-4475-8152-e76605e731fc",
	}

	badTestPaths := []string{
		// Missing the initial /
		"3e782960-a762-4def-8038-a1d0a3cd951d e5c2f479-b9db-4475-8152-e76605e731fc",

		// Leading whitespace
		" / 3e782960-a762-4def-8038-a1d0a3cd951d e5c2f479-b9db-4475-8152-e76605e731fc",
	}

	for i, path := range goodTestPaths {
		if ValidateMensagoPath(path) != true {
			t.Fatalf("ValidateMensagoPath didn't validate good test path #%d", i+1)
		}
	}

	for i, path := range badTestPaths {
		if ValidateMensagoPath(path) != false {
			t.Fatalf("ValidateMensagoPath validated bad test path #%d", i+1)
		}
	}
}

func TestValidateFileName(t *testing.T) {

	testName1 := "1257894000.1024.7cc9a1cf-dfa1-4cb4-bb2b-409a56608b11"
	if ValidateFileName(testName1) != true {
		t.Fatal("ValidateFileName didn't validate a valid name")
	}

	testName2 := " 1257894000.1024.7cc9a1cf-dfa1-4cb4-bb2b-409a56608b11"
	if ValidateFileName(testName2) != false {
		t.Fatal("ValidateFileName subtest #2 validated a bad name")
	}

	testName3 := " / 3e782960-a762-4def-8038-a1d0a3cd951d e5c2f479-b9db-4475-8152-e76605e731fc"
	if ValidateFileName(testName3) != false {
		t.Fatal("ValidateFileName subtest #3 validated a bad name")
	}
}

func TestMPath_SetFromString(t *testing.T) {

	workspacePath := viper.GetString("global.workspace_dir")

	testPath1 := "/ 3e782960-a762-4def-8038-a1d0a3cd951d e5c2f479-b9db-4475-8152-e76605e731fc"
	var anpath LocalMPath

	if anpath.Set(testPath1) != nil {
		t.Fatal("LocalMPath.Set failed to assign a valid path")
	}

	resultPath := filepath.Join(workspacePath, "3e782960-a762-4def-8038-a1d0a3cd951d")
	resultPath = filepath.Join(resultPath, "e5c2f479-b9db-4475-8152-e76605e731fc")
	if anpath.LocalPath != resultPath {
		t.Fatal("LocalMPath.Set failed to set the correct path")
	}
}
