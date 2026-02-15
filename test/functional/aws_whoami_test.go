//go:build functional

package functional

import (
	"os/exec"
	"strings"
	"testing"
)

// TestAWSWhoamiValidated tests the whoami module for AWS identity information
func TestAWSWhoamiValidated(t *testing.T) {
	creds := CheckCredentials()
	if !creds.AWS {
		t.Skip("AWS credentials not available - skipping AWS functional tests")
	}

	// Run Nebula whoami command using go run main.go
	nebulaCmd := exec.Command(
		"go", "run", "main.go", "aws", "recon", "whoami",
		"--profile", "terraform",
		"--file", "test-validated-whoami.json",
	)
	nebulaCmd.Dir = "../../../nebula"

	nebulaOutput, err := nebulaCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Nebula whoami command failed: %v\nOutput: %s", err, string(nebulaOutput))
	}

	// Validate expected console output
	outputStr := string(nebulaOutput)
	
	// Should reference AWS identity
	if !strings.Contains(outputStr, "JSON output written") {
		t.Error("Expected JSON output confirmation not found")
	}

	// Should reference AWS whoami module
	if !strings.Contains(outputStr, "AWS") {
		t.Error("Expected AWS reference not found in output")
	}

	t.Logf("✅ Nebula whoami successfully retrieved AWS identity information")
}