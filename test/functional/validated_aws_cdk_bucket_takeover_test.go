//go:build functional

package functional

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/praetorian-inc/tabularium/pkg/model/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSCDKBucketTakeoverValidated(t *testing.T) {
	// Check AWS credentials
	creds := CheckCredentials()
	if !creds.AWS {
		t.Skip("AWS credentials not available - skipping AWS functional tests")
	}

	// Validate infrastructure exists
	if !ValidateAWSInfrastructure("cdk-bucket-takeover") {
		t.Skip("CDK bucket takeover test infrastructure not deployed - use terraform-devops-engineer agent to deploy")
	}

	// Get infrastructure details for validation
	infraStatus, err := GetInfrastructureStatus("cdk-bucket-takeover")
	if err != nil {
		t.Logf("Could not get infrastructure status: %v", err)
	} else {
		t.Logf("Infrastructure status: %s", infraStatus)
	}

	// Run Nebula CDK bucket takeover command
	outputFile := "test-validated-cdk-bucket-takeover.json"
	nebulaCmd := exec.Command(
		"go", "run", "main.go", "aws", "recon", "cdk-bucket-takeover",
		"--profile", "terraform",
		"--regions", "us-east-1",
		"--cdk-qualifiers", "hnb659fds",
		"--file", outputFile,
	)
	nebulaCmd.Dir = "../../"

	nebulaOutput, err := nebulaCmd.CombinedOutput()
	outputStr := string(nebulaOutput)

	if err != nil {
		t.Fatalf("Nebula CDK bucket takeover command failed: %v\nOutput: %s", err, outputStr)
	}

	// Log command output for debugging
	t.Logf("Nebula CDK scanner output:\n%s", outputStr)

	// Read and parse the JSON output file
	outputPath := filepath.Join("../../aurelian-output", outputFile)
	jsonData, err := os.ReadFile(outputPath)
	require.NoError(t, err, "Should be able to read output file")

	// Parse JSON into Risk objects
	var risks []model.Risk
	err = json.Unmarshal(jsonData, &risks)
	require.NoError(t, err, "Should be able to parse JSON into Risk objects")

	t.Logf("Found %d risk findings", len(risks))

	// Validate expected risk findings
	validateCDKRiskFindings(t, risks)

	// Validate specific vulnerability scenarios
	validateMissingBucketRisk(t, risks)
	validateInsecurePolicyRisk(t, risks)
	validateBootstrapVersionRisk(t, risks)

	// Check command output for expected indicators
	if strings.Contains(outputStr, "cdk-bucket-takeover") || strings.Contains(outputStr, "Risk") {
		t.Logf("✅ Nebula CDK bucket takeover scanner successfully detected vulnerabilities")
	} else {
		t.Logf("Actual output: %s", outputStr)
		t.Error("Expected CDK vulnerability detection indicators not found - investigate scanner")
	}

	// Clean up output file
	if err := os.Remove(outputPath); err != nil {
		t.Logf("Warning: Could not clean up output file %s: %v", outputPath, err)
	}
}

func validateCDKRiskFindings(t *testing.T, risks []model.Risk) {
	// Expected findings based on test infrastructure:
	// - 1-2 HIGH risk findings (missing bucket + optionally outdated bootstrap)
	// - 1 MEDIUM risk finding (insecure policy)
	// - Total: 2-3 risks

	require.GreaterOrEqual(t, len(risks), 2, "Should find at least 2 CDK risk findings")
	require.LessOrEqual(t, len(risks), 3, "Should find at most 3 CDK risk findings")

	// Count risks by severity
	highRisks := 0
	mediumRisks := 0

	for _, risk := range risks {
		assert.Equal(t, "nebula-cdk-scanner", risk.Source, "Risk source should be nebula-cdk-scanner")
		assert.NotEmpty(t, risk.Name, "Risk name should not be empty")
		assert.NotEmpty(t, risk.DNS, "Risk DNS should not be empty")
		assert.NotEmpty(t, risk.Comment, "Risk comment should contain context")

		severity := risk.Severity()
		switch severity {
		case "H": // TriageHigh
			highRisks++
		case "M": // TriageMedium
			mediumRisks++
		default:
			t.Errorf("Unexpected risk severity: %s for risk %s", severity, risk.Name)
		}
	}

	t.Logf("Found %d HIGH risk and %d MEDIUM risk findings", highRisks, mediumRisks)

	// Validate severity distribution
	assert.GreaterOrEqual(t, highRisks, 1, "Should find at least 1 HIGH risk (missing bucket)")
	assert.LessOrEqual(t, highRisks, 2, "Should find at most 2 HIGH risks (missing bucket + outdated bootstrap)")
	assert.Equal(t, 1, mediumRisks, "Should find exactly 1 MEDIUM risk (insecure policy)")
}

func validateMissingBucketRisk(t *testing.T, risks []model.Risk) {
	// Look for the missing bucket risk
	missingBucketFound := false

	for _, risk := range risks {
		if risk.Name == "cdk-bucket-takeover" {
			missingBucketFound = true

			assert.Equal(t, "H", risk.Severity(), "Missing bucket should be HIGH risk")
			assert.Contains(t, risk.Comment, "cdk-hnb659fds-assets-", "Comment should mention expected bucket name")
			assert.Contains(t, risk.Comment, "411435703965", "Comment should contain account ID")
			assert.Contains(t, risk.Comment, "us-east-1", "Comment should contain region")

			t.Logf("✅ Missing bucket risk validated: %s", risk.Name)
			break
		}
	}

	assert.True(t, missingBucketFound, "Should find missing bucket risk (cdk-bucket-takeover)")
}

func validateInsecurePolicyRisk(t *testing.T, risks []model.Risk) {
	// Look for the insecure policy risk
	policyRiskFound := false

	for _, risk := range risks {
		if risk.Name == "cdk-policy-unrestricted" {
			policyRiskFound = true

			assert.Equal(t, "M", risk.Severity(), "Insecure policy should be MEDIUM risk")
			assert.Contains(t, risk.Comment, "file-publishing-role", "Comment should mention FilePublishingRole")
			assert.Contains(t, risk.Comment, "hnb659fds", "Comment should mention qualifier")

			t.Logf("✅ Insecure policy risk validated: %s", risk.Name)
			break
		}
	}

	assert.True(t, policyRiskFound, "Should find insecure policy risk (cdk-policy-unrestricted)")
}

func validateBootstrapVersionRisk(t *testing.T, risks []model.Risk) {
	// Look for bootstrap version risk (may or may not exist depending on infrastructure)
	bootstrapRiskFound := false

	for _, risk := range risks {
		if risk.Name == "cdk-bootstrap-outdated" || risk.Name == "cdk-bootstrap-missing" {
			bootstrapRiskFound = true

			if risk.Name == "cdk-bootstrap-outdated" {
				assert.Equal(t, "H", risk.Severity(), "Outdated bootstrap should be HIGH risk")
				assert.Contains(t, risk.Comment, "Version: 20", "Comment should mention version 20")
			}

			assert.Contains(t, risk.Comment, "hnb659fds", "Comment should mention qualifier")
			assert.Contains(t, risk.Comment, "us-east-1", "Comment should mention region")

			t.Logf("✅ Bootstrap version risk validated: %s", risk.Name)
			break
		}
	}

	if bootstrapRiskFound {
		t.Logf("Bootstrap version risk detected and validated")
	} else {
		t.Logf("No bootstrap version risk found (may be expected depending on infrastructure)")
	}
}

// Test helper to verify CDK role detection specifically
func TestAWSCDKRoleDetectionValidated(t *testing.T) {
	creds := CheckCredentials()
	if !creds.AWS {
		t.Skip("AWS credentials not available - skipping AWS functional tests")
	}

	// Test just the role detection component
	nebulaCmd := exec.Command(
		"go", "run", "main.go", "aws", "recon", "cdk-bucket-takeover",
		"--profile", "terraform",
		"--regions", "us-east-1",
		"--cdk-qualifiers", "hnb659fds",
		"--file", "test-cdk-roles.json",
	)
	nebulaCmd.Dir = "../../"

	output, err := nebulaCmd.CombinedOutput()

	if err != nil {
		t.Logf("Command output: %s", string(output))
		t.Fatalf("CDK role detection failed: %v", err)
	}

	outputStr := string(output)

	// Should find the CDK roles we created
	expectedIndicators := []string{
		"file-publishing-role", // Should detect FilePublishingRole
		"cfn-exec-role",        // Should detect CloudFormation execution role
		"411435703965",         // Account ID should appear
		"us-east-1",            // Region should appear
		"hnb659fds",            // Qualifier should appear
	}

	for _, indicator := range expectedIndicators {
		if !strings.Contains(outputStr, indicator) {
			t.Errorf("Expected indicator '%s' not found in output", indicator)
		}
	}

	t.Logf("✅ CDK role detection working correctly")
}
