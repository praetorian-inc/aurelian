//go:build functional

package functional

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestAWSPublicResourcesLambdaFunctionUrlAuthTypeNone validates that Lambda functions
// with FunctionUrlAuthType: NONE are correctly detected as public resources
func TestAWSPublicResourcesLambdaFunctionUrlAuthTypeNone(t *testing.T) {
	// 1. Check AWS credentials
	creds := CheckCredentials()
	if !creds.AWS {
		t.Skip("AWS credentials not available - skipping AWS functional tests")
	}

	// 2. Validate infrastructure exists
	if !ValidateAWSInfrastructure("public-resources") {
		t.Skip("Public resources infrastructure not deployed - use terraform-devops-engineer agent to deploy")
	}

	// 3. Run nebula public-resources command targeting Lambda functions
	nebulaCmd := exec.Command(
		"go", "run", "main.go", "aws", "recon", "public-resources",
		"--profile", "terraform",
		"--resource-type", "AWS::Lambda::Function",
		"--regions", "us-east-2",
		"--file", "test-public-resources-lambda.json",
	)
	nebulaCmd.Dir = "../../../nebula"

	output, err := nebulaCmd.CombinedOutput()
	outputStr := string(output)

	if err != nil {
		t.Fatalf("Nebula public-resources command failed: %v\nOutput: %s", err, outputStr)
	}

	// 4. Validate specific Lambda function detection in CLI output
	if strings.Contains(outputStr, "vuln-functionurlauthtype-none") {
		t.Logf("✓ Lambda function with AuthType NONE detected in CLI output")
	} else {
		t.Logf("CLI output: %s", outputStr)
		t.Error("Expected vuln-functionurlauthtype-none not found in CLI output")
	}

	// 5. Validate JSON output file creation and content
	jsonPath := "../../../nebula/aurelian-output/test-public-resources-lambda-terraform.json"
	if _, err := os.Stat(jsonPath); err == nil {
		jsonData, readErr := os.ReadFile(jsonPath)
		if readErr != nil {
			t.Fatalf("Failed to read JSON output: %v", readErr)
		}

		jsonStr := string(jsonData)
		if strings.Contains(jsonStr, "vuln-functionurlauthtype-none") {
			t.Logf("✓ Lambda function detected in JSON output")
		} else {
			t.Error("Expected function not found in JSON output")
		}

		// Parse JSON and validate specific fields
		var results []map[string]any
		if json.Unmarshal(jsonData, &results) == nil {
			found := false
			for _, result := range results {
				// Check if ARN contains function name - could be string or ARN object
				var arnStr string
				if arn, ok := result["Arn"].(string); ok {
					arnStr = arn
				} else if arnObj, ok := result["Arn"].(map[string]any); ok {
					if resource, ok := arnObj["Resource"].(string); ok {
						arnStr = resource
					}
				}

				if strings.Contains(arnStr, "vuln-functionurlauthtype-none") {
					found = true
					t.Logf("✓ Function ARN found: %s", arnStr)

					// Validate evaluation reasons mention AuthType or related conditions
					if reasons, ok := result["EvaluationReasons"].([]any); ok {
						reasonsStr := fmt.Sprintf("%v", reasons)
						if strings.Contains(reasonsStr, "AuthType") ||
							strings.Contains(reasonsStr, "apigateway") ||
							strings.Contains(reasonsStr, "FunctionUrl") {
							t.Logf("✓ AuthType/API Gateway evaluation detected: %s", reasonsStr)
						} else {
							t.Logf("Evaluation reasons: %v", reasons)
							t.Error("AuthType/FunctionUrl evaluation not found in reasons")
						}
					}

					// Validate that actions include lambda actions
					if actions, ok := result["Actions"].([]any); ok {
						actionsStr := fmt.Sprintf("%v", actions)
						if strings.Contains(actionsStr, "lambda:") {
							t.Logf("✓ Lambda actions detected: %s", actionsStr)
						} else {
							t.Error("Lambda actions not found")
						}
					}
					break
				}
			}

			if !found {
				t.Error("Function with vuln-functionurlauthtype-none not found in parsed JSON results")
			}
		} else {
			t.Error("Failed to parse JSON output")
		}
	} else {
		t.Error("JSON output file not created at expected path")
	}
}

// TestAWSPublicResourcesS3SecureTransportAnonymous validates that S3 buckets
// with SecureTransport conditions and Anonymous principal access are detected
func TestAWSPublicResourcesS3SecureTransportAnonymous(t *testing.T) {
	// 1. Check AWS credentials
	creds := CheckCredentials()
	if !creds.AWS {
		t.Skip("AWS credentials not available - skipping AWS functional tests")
	}

	// 2. Validate infrastructure exists
	if !ValidateAWSInfrastructure("public-resources") {
		t.Skip("Public resources infrastructure not deployed - use terraform-devops-engineer agent to deploy")
	}

	// 3. Run nebula public-resources command targeting S3 buckets
	nebulaCmd := exec.Command(
		"go", "run", "main.go", "aws", "recon", "public-resources",
		"--profile", "terraform",
		"--resource-type", "AWS::S3::Bucket",
		"--regions", "us-east-2",
		"--file", "test-public-resources-s3.json",
	)
	nebulaCmd.Dir = "../../../nebula"

	output, err := nebulaCmd.CombinedOutput()
	outputStr := string(output)

	if err != nil {
		t.Fatalf("Nebula public-resources command failed: %v\nOutput: %s", err, outputStr)
	}

	// 4. Validate specific S3 bucket detection in CLI output
	if strings.Contains(outputStr, "vuln-securetransport-anonymous") {
		t.Logf("✓ S3 bucket with SecureTransport + Anonymous access detected in CLI output")
	} else {
		t.Logf("CLI output: %s", outputStr)
		t.Error("Expected vuln-securetransport-anonymous not found in CLI output")
	}

	// 5. Validate JSON output file creation and content
	jsonPath := "../../../nebula/aurelian-output/test-public-resources-s3-terraform.json"
	if _, err := os.Stat(jsonPath); err == nil {
		jsonData, readErr := os.ReadFile(jsonPath)
		if readErr != nil {
			t.Fatalf("Failed to read JSON output: %v", readErr)
		}

		jsonStr := string(jsonData)
		if strings.Contains(jsonStr, "vuln-securetransport-anonymous") {
			t.Logf("✓ S3 bucket detected in JSON output")
		} else {
			t.Error("Expected bucket not found in JSON output")
		}

		// Parse JSON and validate specific fields
		var results []map[string]any
		if json.Unmarshal(jsonData, &results) == nil {
			found := false
			for _, result := range results {
				// Check if ARN contains bucket name - could be string or ARN object
				var arnStr string
				if arn, ok := result["Arn"].(string); ok {
					arnStr = arn
				} else if arnObj, ok := result["Arn"].(map[string]any); ok {
					if resource, ok := arnObj["Resource"].(string); ok {
						arnStr = resource
					}
				}

				if strings.Contains(arnStr, "vuln-securetransport-anonymous") {
					found = true
					t.Logf("✓ Bucket ARN found: %s", arnStr)

					// Validate evaluation reasons mention SecureTransport, Anonymous, or PrincipalType
					if reasons, ok := result["EvaluationReasons"].([]any); ok {
						reasonsStr := fmt.Sprintf("%v", reasons)
						if strings.Contains(reasonsStr, "SecureTransport") ||
							strings.Contains(reasonsStr, "Anonymous") ||
							strings.Contains(reasonsStr, "PrincipalType") {
							t.Logf("✓ SecureTransport/Anonymous evaluation detected: %s", reasonsStr)
						} else {
							t.Logf("Evaluation reasons: %v", reasons)
							t.Error("SecureTransport/Anonymous evaluation not found in reasons")
						}
					}

					// Validate that actions include S3 actions
					if actions, ok := result["Actions"].([]any); ok {
						actionsStr := fmt.Sprintf("%v", actions)
						if strings.Contains(actionsStr, "s3:") {
							t.Logf("✓ S3 actions detected: %s", actionsStr)
						} else {
							t.Error("S3 actions not found")
						}
					}
					break
				}
			}

			if !found {
				t.Error("Bucket with vuln-securetransport-anonymous not found in parsed JSON results")
			}
		} else {
			t.Error("Failed to parse JSON output")
		}
	} else {
		t.Error("JSON output file not created at expected path")
	}
}

// TestAWSPublicResourcesComprehensive runs a comprehensive test without resource-type
// filtering to validate both Lambda and S3 scenarios are detected together
func TestAWSPublicResourcesComprehensive(t *testing.T) {
	// 1. Check AWS credentials
	creds := CheckCredentials()
	if !creds.AWS {
		t.Skip("AWS credentials not available - skipping AWS functional tests")
	}

	// 2. Validate infrastructure exists
	if !ValidateAWSInfrastructure("public-resources") {
		t.Skip("Public resources infrastructure not deployed - use terraform-devops-engineer agent to deploy")
	}

	// 3. Run nebula public-resources command without resource-type filter
	nebulaCmd := exec.Command(
		"go", "run", "main.go", "aws", "recon", "public-resources",
		"--profile", "terraform",
		"--regions", "us-east-2",
		"--file", "test-public-resources-comprehensive.json",
	)
	nebulaCmd.Dir = "../../../nebula"

	output, err := nebulaCmd.CombinedOutput()
	outputStr := string(output)

	if err != nil {
		t.Fatalf("Nebula comprehensive public-resources command failed: %v\nOutput: %s", err, outputStr)
	}

	// 4. Validate both resources detected in CLI output
	lambdaFound := strings.Contains(outputStr, "vuln-functionurlauthtype-none")
	s3Found := strings.Contains(outputStr, "vuln-securetransport-anonymous")

	if lambdaFound && s3Found {
		t.Logf("✓ Both Lambda and S3 public resources detected in comprehensive scan")
	} else {
		t.Logf("CLI output: %s", outputStr)
		if !lambdaFound {
			t.Error("Lambda function vuln-functionurlauthtype-none not found in comprehensive scan")
		}
		if !s3Found {
			t.Error("S3 bucket vuln-securetransport-anonymous not found in comprehensive scan")
		}
	}

	// 5. Validate JSON output contains both resources
	jsonPath := "../../../nebula/aurelian-output/test-public-resources-comprehensive-terraform.json"
	if _, err := os.Stat(jsonPath); err == nil {
		jsonData, readErr := os.ReadFile(jsonPath)
		if readErr != nil {
			t.Fatalf("Failed to read comprehensive JSON output: %v", readErr)
		}

		var results []map[string]any
		if json.Unmarshal(jsonData, &results) == nil {
			lambdaFound := false
			s3Found := false

			for _, result := range results {
				// Check if ARN contains resource name - could be string or ARN object
				var arnStr string
				if arn, ok := result["Arn"].(string); ok {
					arnStr = arn
				} else if arnObj, ok := result["Arn"].(map[string]any); ok {
					if resource, ok := arnObj["Resource"].(string); ok {
						arnStr = resource
					}
				}

				if strings.Contains(arnStr, "vuln-functionurlauthtype-none") {
					lambdaFound = true
					t.Logf("✓ Lambda function found in comprehensive JSON: %s", arnStr)
				}
				if strings.Contains(arnStr, "vuln-securetransport-anonymous") {
					s3Found = true
					t.Logf("✓ S3 bucket found in comprehensive JSON: %s", arnStr)
				}
			}

			if lambdaFound && s3Found {
				t.Logf("✓ Both public resources validated in comprehensive JSON output")
				t.Logf("Total public resources detected: %d", len(results))
			} else {
				if !lambdaFound {
					t.Error("Lambda function not found in comprehensive JSON results")
				}
				if !s3Found {
					t.Error("S3 bucket not found in comprehensive JSON results")
				}
			}
		} else {
			t.Error("Failed to parse comprehensive JSON output")
		}
	} else {
		t.Error("Comprehensive JSON output file not created")
	}
}
