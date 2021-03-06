package fshandler

import (
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

func TestValidateMensagoPath(t *testing.T) {

	testPath1 := "/ 3e782960-a762-4def-8038-a1d0a3cd951d e5c2f479-b9db-4475-8152-e76605e731fc"
	if ValidateMensagoPath(testPath1) != true {
		t.Fatal("ValidateMensagoPath didn't validate a valid path")
	}

	testPath2 := "3e782960-a762-4def-8038-a1d0a3cd951d e5c2f479-b9db-4475-8152-e76605e731fc"
	if ValidateMensagoPath(testPath2) != false {
		t.Fatal("ValidateMensagoPath subtest #2 validated a bad path")
	}

	testPath3 := " / 3e782960-a762-4def-8038-a1d0a3cd951d e5c2f479-b9db-4475-8152-e76605e731fc"
	if ValidateMensagoPath(testPath3) != false {
		t.Fatal("ValidateMensagoPath subtest #3 validated a bad path")
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

func TestAnPath_SetFromString(t *testing.T) {

	workspacePath := viper.GetString("global.workspace_dir")

	testPath1 := "/ 3e782960-a762-4def-8038-a1d0a3cd951d e5c2f479-b9db-4475-8152-e76605e731fc"
	var anpath LocalAnPath

	if anpath.Set(testPath1) != nil {
		t.Fatal("LocalAnPath.Set failed to assign a valid path")
	}

	resultPath := filepath.Join(workspacePath, "3e782960-a762-4def-8038-a1d0a3cd951d")
	resultPath = filepath.Join(resultPath, "e5c2f479-b9db-4475-8152-e76605e731fc")
	if anpath.LocalPath != resultPath {
		t.Fatal("LocalAnPath.Set failed to set the correct path")
	}
}
