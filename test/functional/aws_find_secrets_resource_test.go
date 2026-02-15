//go:build functional

package functional

import (
	"os/exec"
	"strings"
	"testing"
)

// TestAWSFindSecretsResourceValidated tests the find-secrets-resource module for targeted secret scanning
func TestAWSFindSecretsResourceValidated(t *testing.T) {
	creds := CheckCredentials()
	if !creds.AWS {
		t.Skip("AWS credentials not available - skipping AWS functional tests")
	}

	// Run Nebula find-secrets-resource command using go run main.go
	nebulaCmd := exec.Command(
		"go", "run", "main.go", "aws", "recon", "find-secrets-resource",
		"--profile", "terraform",
		"--resource-type", "AWS::Lambda::Function",
		"--regions", "us-east-2",
		"--file", "test-validated-find-secrets-resource.json",
	)
	nebulaCmd.Dir = "../../../nebula"

	nebulaOutput, err := nebulaCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Nebula find-secrets-resource command failed: %v\nOutput: %s", err, string(nebulaOutput))
	}

	// Validate expected console output
	outputStr := string(nebulaOutput)
	
	// Should show successful completion
	if !strings.Contains(outputStr, "JSON output written") {
		t.Error("Expected JSON output confirmation not found")
	}

	// Should reference the specified resource type
	if !strings.Contains(outputStr, "AWS::Lambda::Function") {
		t.Error("Expected resource type AWS::Lambda::Function not found in output")
	}

	t.Logf("✅ Nebula find-secrets-resource successfully scanned Lambda functions for secrets")
}