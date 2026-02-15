//go:build functional

package functional

import (
	"os/exec"
	"strings"
	"testing"
)

// TestAWSSummaryValidated tests the summary module for AWS account overview
func TestAWSSummaryValidated(t *testing.T) {
	creds := CheckCredentials()
	if !creds.AWS {
		t.Skip("AWS credentials not available - skipping AWS functional tests")
	}

	// Run Nebula summary command using go run main.go
	nebulaCmd := exec.Command(
		"go", "run", "main.go", "aws", "recon", "summary",
		"--profile", "terraform",
		"--file", "test-validated-summary.json",
	)
	nebulaCmd.Dir = "../../../nebula"

	nebulaOutput, err := nebulaCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Nebula summary command failed: %v\nOutput: %s", err, string(nebulaOutput))
	}

	// Validate expected console output
	outputStr := string(nebulaOutput)
	
	// Should show successful completion
	if !strings.Contains(outputStr, "JSON output written") {
		t.Error("Expected JSON output confirmation not found")
	}

	// Should reference AWS summary module
	if !strings.Contains(outputStr, "AWS") {
		t.Error("Expected AWS reference not found in output")
	}

	t.Logf("✅ Nebula summary successfully generated AWS account summary")
}