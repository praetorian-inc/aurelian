//go:build functional

package functional

import (
	"os/exec"
	"strings"
	"testing"
)

// TestAWSAccountAuthDetailsValidated tests the account-auth-details module for AWS IAM information
func TestAWSAccountAuthDetailsValidated(t *testing.T) {
	creds := CheckCredentials()
	if !creds.AWS {
		t.Skip("AWS credentials not available - skipping AWS functional tests")
	}

	// Run Nebula account-auth-details command using go run main.go
	nebulaCmd := exec.Command(
		"go", "run", "main.go", "aws", "recon", "account-auth-details",
		"--profile", "terraform",
		"--file", "test-validated-account-auth-details.json",
	)
	nebulaCmd.Dir = "../../../nebula"

	nebulaOutput, err := nebulaCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Nebula account-auth-details command failed: %v\nOutput: %s", err, string(nebulaOutput))
	}

	// Validate expected console output
	outputStr := string(nebulaOutput)
	
	// Should show successful completion
	if !strings.Contains(outputStr, "JSON output written") {
		t.Error("Expected JSON output confirmation not found")
	}

	t.Logf("✅ Nebula account-auth-details successfully retrieved AWS IAM information")
}