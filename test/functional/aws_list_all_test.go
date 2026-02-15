//go:build functional

package functional

import (
	"os/exec"
	"strings"
	"testing"
)

// TestAWSListAllValidated tests the list-all module for comprehensive AWS resource enumeration
func TestAWSListAllValidated(t *testing.T) {
	creds := CheckCredentials()
	if !creds.AWS {
		t.Skip("AWS credentials not available - skipping AWS functional tests")
	}

	// Run Nebula list-all command using go run main.go with summary scan
	nebulaCmd := exec.Command(
		"go", "run", "main.go", "aws", "recon", "list-all",
		"--profile", "terraform",
		"--scan-type", "summary",
		"--file", "test-validated-list-all.json",
	)
	nebulaCmd.Dir = "../../../nebula"

	nebulaOutput, err := nebulaCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Nebula list-all command failed: %v\nOutput: %s", err, string(nebulaOutput))
	}

	// Validate expected console output
	outputStr := string(nebulaOutput)
	
	// Should show successful completion
	if !strings.Contains(outputStr, "JSON output written") {
		t.Error("Expected JSON output confirmation not found")
	}

	// Should reference AWS list-all module
	if !strings.Contains(outputStr, "AWS") {
		t.Error("Expected AWS reference not found in output")
	}

	t.Logf("✅ Nebula list-all successfully enumerated AWS resources")
}