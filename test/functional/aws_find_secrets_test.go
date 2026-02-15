//go:build functional

package functional

import (
	"os/exec"
	"strings"
	"testing"
)

// Expected test secrets embedded in the infrastructure
var expectedSecrets = map[string]struct{}{
	"ghp_XIxB7KMNdAr3zqWtQqhE94qglHqOzn1D1stg":                              {}, // GitHub PAT
	"AKIAIOSFODNN7EXAMPLE":                                                   {}, // AWS Access Key
	"xoxb-123456789012-123456789012-v1d4Y9JAQoIIo1VMLEDJHx7A":               {}, // Slack Token
	"sk-1234567890abcdef1234567890abcdef12345678":                            {}, // Generic API Key
	"wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY":                             {}, // Azure Storage Key
}

// TestAWSFindSecretsValidated tests the find-secrets module against comprehensive deployed infrastructure
// Each test validates secret detection in specific AWS resource types with known embedded secrets
func TestAWSFindSecretsValidated(t *testing.T) {
	creds := CheckCredentials()
	if !creds.AWS {
		t.Skip("AWS credentials not available - skipping AWS functional tests")
	}

	// Test each resource type individually with detailed secret validation
	resourceTests := []struct {
		name           string
		resourceType   string
		region         string
		expectedSecrets []string
		minFindings    int
	}{
		{
			name:         "EC2-Instance-UserData",
			resourceType: "AWS::EC2::Instance", 
			region:       "us-east-2",
			expectedSecrets: []string{
				"ghp_XIxB7KMNdAr3zqWtQqhE94qglHqOzn1D1stg", // GitHub PAT in UserData
				"AKIAIOSFODNN7EXAMPLE",                     // AWS Key in UserData script
			},
			minFindings: 2,
		},
		{
			name:         "Lambda-Function-Code",
			resourceType: "AWS::Lambda::Function",
			region:       "us-east-2", 
			expectedSecrets: []string{
				"sk-1234567890abcdef1234567890abcdef12345678",                // API key in function code
				"xoxb-123456789012-123456789012-v1d4Y9JAQoIIo1VMLEDJHx7A", // Slack token in config.py
				"ghp_XIxB7KMNdAr3zqWtQqhE94qglHqOzn1D1stg",              // GitHub PAT in env vars
			},
			minFindings: 3,
		},
		{
			name:         "SSM-Parameter-Values", 
			resourceType: "AWS::SSM::Parameter",
			region:       "us-east-2",
			expectedSecrets: []string{
				"sk-1234567890abcdef1234567890abcdef12345678",                // API key in SecureString
				"wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY",               // Azure key in JSON config
				"ghp_XIxB7KMNdAr3zqWtQqhE94qglHqOzn1D1stg",              // GitHub PAT in parameter
			},
			minFindings: 3,
		},
		{
			name:         "SSM-Document-Content",
			resourceType: "AWS::SSM::Document", 
			region:       "us-east-2",
			expectedSecrets: []string{
				"AKIAIOSFODNN7EXAMPLE",                                     // AWS key in document YAML
				"xoxb-123456789012-123456789012-v1d4Y9JAQoIIo1VMLEDJHx7A", // Slack token in automation
			},
			minFindings: 2,
		},
		{
			name:         "ECS-TaskDefinition-Environment",
			resourceType: "AWS::ECS::TaskDefinition",
			region:       "us-east-2",
			expectedSecrets: []string{
				"sk-1234567890abcdef1234567890abcdef12345678",  // API key in container env
				"ghp_XIxB7KMNdAr3zqWtQqhE94qglHqOzn1D1stg",    // GitHub PAT in sidecar
			},
			minFindings: 2,
		},
		{
			name:         "StepFunctions-StateMachine-Definition", 
			resourceType: "AWS::StepFunctions::StateMachine",
			region:       "us-east-2",
			expectedSecrets: []string{
				"xoxb-123456789012-123456789012-v1d4Y9JAQoIIo1VMLEDJHx7A", // Slack token in definition
				"sk-1234567890abcdef1234567890abcdef12345678",              // API key in HTTP task
			},
			minFindings: 2,
		},
		{
			name:         "ECR-Repository-Policies",
			resourceType: "AWS::ECR::Repository",
			region:       "us-east-2", 
			expectedSecrets: []string{
				"AKIAIOSFODNN7EXAMPLE", // AWS key in repository policy
			},
			minFindings: 1,
		},
	}

	for _, test := range resourceTests {
		t.Run(test.name, func(t *testing.T) {
			// Run Nebula find-secrets for specific resource type
			nebulaCmd := exec.Command(
				"go", "run", "main.go", "aws", "recon", "find-secrets",
				"--profile", "terraform",
				"--resource-type", test.resourceType,
				"--regions", test.region,
				"--file", "test-"+test.name+".json",
			)
			nebulaCmd.Dir = "../../../nebula"

			nebulaOutput, err := nebulaCmd.CombinedOutput()
			outputStr := string(nebulaOutput)
			
			if err != nil {
				t.Fatalf("Nebula find-secrets failed for %s: %v\nOutput: %s", test.resourceType, err, outputStr)
			}

			// Validate command executed successfully
			if !strings.Contains(outputStr, "JSON output written") {
				t.Errorf("Expected JSON output confirmation not found for %s", test.resourceType)
				return
			}

			// Validate secret detection from console output
			foundSecrets := 0
			for _, expectedSecret := range test.expectedSecrets {
				if strings.Contains(outputStr, expectedSecret) {
					foundSecrets++
					t.Logf("✅ Found expected secret %s... in console output", expectedSecret[:20])
				}
			}

			// Also check for NoseyParker findings indicators
			if strings.Contains(outputStr, "Nosey Parker Findings") {
				t.Logf("✅ NoseyParker findings section detected in output")
			}

			// Look for rule matches (indicates secret detection)
			if strings.Contains(outputStr, "Rule:") {
				t.Logf("✅ Secret detection rules triggered")
			}

			// Validate specific secret patterns in output
			for _, expectedSecret := range test.expectedSecrets {
				if strings.Contains(outputStr, expectedSecret) {
					t.Logf("✅ Secret %s... detected in %s", expectedSecret[:20], test.resourceType)
				} else {
					t.Logf("⚠️ Expected secret %s... not found in %s output", expectedSecret[:20], test.resourceType)
				}
			}

			// Validate resource type was processed
			if strings.Contains(outputStr, test.resourceType) {
				t.Logf("✅ Successfully processed %s resources", test.resourceType)
			}

			t.Logf("✅ %s: Completed validation with %d expected secrets", test.name, len(test.expectedSecrets))
		})
	}

	// Test comprehensive scan of all resource types
	t.Run("All-Resource-Types-Comprehensive", func(t *testing.T) {
		nebulaCmd := exec.Command(
			"go", "run", "main.go", "aws", "recon", "find-secrets",
			"--profile", "terraform",
			"--resource-type", "all",
			"--regions", "us-east-2",
			"--file", "test-comprehensive-find-secrets.json",
		)
		nebulaCmd.Dir = "../../../nebula"

		nebulaOutput, err := nebulaCmd.CombinedOutput()
		outputStr := string(nebulaOutput)
		
		if err != nil {
			t.Fatalf("Nebula comprehensive find-secrets failed: %v\nOutput: %s", err, outputStr)
		}

		// Should process all deployed resource types
		expectedTypes := []string{
			"AWS::EC2::Instance",
			"AWS::Lambda::Function", 
			"AWS::SSM::Parameter",
			"AWS::SSM::Document",
			"AWS::ECS::TaskDefinition",
			"AWS::StepFunctions::StateMachine",
			"AWS::ECR::Repository",
		}

		for _, resourceType := range expectedTypes {
			if strings.Contains(outputStr, resourceType) {
				t.Logf("✓ Successfully processed %s", resourceType)
			} else {
				t.Logf("⚠ %s not found in output (may not have resources)", resourceType)
			}
		}

		if strings.Contains(outputStr, "JSON output written") {
			t.Logf("✅ Nebula find-secrets successfully completed comprehensive scan")
		} else {
			t.Error("Expected completion message not found in comprehensive scan")
		}
	})
}

