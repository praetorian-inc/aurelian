//go:build functional

package functional

import (
	"os/exec"
	"strings"
	"testing"
)

// TestAWSListValidated tests the list module against real deployed infrastructure
// Validates resource enumeration functionality without requiring specific infrastructure state
func TestAWSListValidated(t *testing.T) {
	creds := CheckCredentials()
	if !creds.AWS {
		t.Skip("AWS credentials not available - skipping AWS functional tests")
	}

	// Run Nebula list command using go run main.go
	nebulaCmd := exec.Command(
		"go", "run", "main.go", "aws", "recon", "list",
		"--profile", "terraform",
		"--resource-type", "AWS::EC2::Instance",
		"--regions", "us-east-2", 
		"--file", "test-validated-list.json",
	)
	nebulaCmd.Dir = "../../../nebula"

	nebulaOutput, err := nebulaCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Nebula list command failed: %v\nOutput: %s", err, string(nebulaOutput))
	}

	// Validate expected console output
	outputStr := string(nebulaOutput)
	
	// Should reference listing EC2 instances
	if !strings.Contains(outputStr, "AWS::EC2::Instance") {
		t.Error("Expected resource type AWS::EC2::Instance not found in output")
	}
	
	if !strings.Contains(outputStr, "us-east-2") {
		t.Error("Expected region us-east-2 not found in output")
	}
	
	// Should show successful completion
	if !strings.Contains(outputStr, "JSON output written") {
		t.Error("Expected JSON output confirmation not found")
	}

	// Should reference AWS List Resources module
	if !strings.Contains(outputStr, "AWS List Resources") {
		t.Error("Expected module name not found in output")
	}

	t.Logf("✅ Nebula list successfully enumerated EC2 instances")
}