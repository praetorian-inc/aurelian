//go:build functional

package functional

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// ValidateAWSInfrastructure checks if the specified AWS infrastructure module is deployed
func ValidateAWSInfrastructure(moduleName string) bool {
	terraformDir, ok := getModuleDir(moduleName)
	if !ok {
		return false
	}

	// Use terraform show -json to check state
	cmd := exec.Command("terraform", "-chdir="+terraformDir, "show", "-json")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	// Parse terraform state JSON
	var state map[string]interface{}
	if err := json.Unmarshal(output, &state); err != nil {
		return false
	}

	// Check for expected resources based on module
	switch moduleName {
	case "find-secrets":
		return validateFindSecretsResources(state)
	case "list":
		return validateListResources(state)
	case "public-resources":
		return validatePublicResourcesResources(state)
	default:
		return false
	}
}

// GetInfrastructureStatus returns detailed status information about the infrastructure
func GetInfrastructureStatus(moduleName string) (string, error) {
	terraformDir, ok := getModuleDir(moduleName)
	if !ok {
		return "", fmt.Errorf("unknown module: %s", moduleName)
	}

	// Use terraform show -json to get detailed state
	cmd := exec.Command("terraform", "-chdir="+terraformDir, "show", "-json")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("terraform show failed: %v", err)
	}

	// Parse terraform state JSON
	var state map[string]interface{}
	if err := json.Unmarshal(output, &state); err != nil {
		return "", fmt.Errorf("failed to parse terraform state: %v", err)
	}

	return formatStateInfo(moduleName, state), nil
}

// getModuleDir returns the terraform directory for the given module
func getModuleDir(moduleName string) (string, bool) {
	baseDir := "../../../Nebula-Cloud-Infrastructures/Testing Infrastructure/AWS"
	
	switch moduleName {
	case "find-secrets":
		return filepath.Join(baseDir, "nebula-find-secrets"), true
	case "list":
		return filepath.Join(baseDir, "nebula-list"), true
	case "public-resources":
		return filepath.Join(baseDir, "public-resources"), true
	default:
		return "", false
	}
}

// validateFindSecretsResources checks if find-secrets infrastructure has expected resources
func validateFindSecretsResources(state map[string]interface{}) bool {
	values, ok := state["values"].(map[string]interface{})
	if !ok {
		return false
	}

	rootModule, ok := values["root_module"].(map[string]interface{})
	if !ok {
		return false
	}

	resources, ok := rootModule["resources"].([]interface{})
	if !ok {
		return false
	}

	// Look for Lambda function and IAM role
	hasLambda := false
	hasIAMRole := false

	for _, resource := range resources {
		if resourceMap, ok := resource.(map[string]interface{}); ok {
			resourceType, _ := resourceMap["type"].(string)
			resourceName, _ := resourceMap["name"].(string)

			if resourceType == "aws_lambda_function" && strings.Contains(resourceName, "test_secrets_lambda") {
				// Check if values contain the expected function name pattern
				if values, ok := resourceMap["values"].(map[string]interface{}); ok {
					if functionName, ok := values["function_name"].(string); ok {
						if strings.Contains(functionName, "nebula-test-find-secrets") {
							hasLambda = true
						}
					}
				}
			}

			if resourceType == "aws_iam_role" && strings.Contains(resourceName, "lambda_role") {
				// Check if values contain the expected role name pattern
				if values, ok := resourceMap["values"].(map[string]interface{}); ok {
					if roleName, ok := values["name"].(string); ok {
						if strings.Contains(roleName, "nebula-test-lambda-role") {
							hasIAMRole = true
						}
					}
				}
			}
		}
	}

	return hasLambda && hasIAMRole
}

// validateListResources checks if list infrastructure has expected resources
func validateListResources(state map[string]interface{}) bool {
	values, ok := state["values"].(map[string]interface{})
	if !ok {
		return false
	}

	rootModule, ok := values["root_module"].(map[string]interface{})
	if !ok {
		return false
	}

	resources, ok := rootModule["resources"].([]interface{})
	if !ok {
		return false
	}

	// Look for EC2 instance
	for _, resource := range resources {
		if resourceMap, ok := resource.(map[string]interface{}); ok {
			resourceType, _ := resourceMap["type"].(string)
			resourceName, _ := resourceMap["name"].(string)

			if resourceType == "aws_instance" && strings.Contains(resourceName, "test_instance") {
				// Check if values contain the expected tags
				if values, ok := resourceMap["values"].(map[string]interface{}); ok {
					if tags, ok := values["tags"].(map[string]interface{}); ok {
						if name, ok := tags["Name"].(string); ok {
							if strings.Contains(name, "nebula-test-list") {
								return true
							}
						}
					}
				}
			}
		}
	}

	return false
}

// validatePublicResourcesResources checks if public-resources infrastructure has expected resources
func validatePublicResourcesResources(state map[string]interface{}) bool {
	values, ok := state["values"].(map[string]interface{})
	if !ok {
		return false
	}

	rootModule, ok := values["root_module"].(map[string]interface{})
	if !ok {
		return false
	}

	// Look for Lambda function with vuln-functionurlauthtype-none and S3 bucket with vuln-securetransport-anonymous
	hasLambdaFunction := false
	hasS3Bucket := false

	// Check root module resources first
	if resources, ok := rootModule["resources"].([]interface{}); ok {
		for _, resource := range resources {
			if resourceMap, ok := resource.(map[string]interface{}); ok {
				resourceType, _ := resourceMap["type"].(string)
				
				if resourceType == "aws_lambda_function" {
					if values, ok := resourceMap["values"].(map[string]interface{}); ok {
						if functionName, ok := values["function_name"].(string); ok {
							if strings.Contains(functionName, "vuln-functionurlauthtype-none") {
								hasLambdaFunction = true
							}
						}
					}
				}

				if resourceType == "aws_s3_bucket" {
					if values, ok := resourceMap["values"].(map[string]interface{}); ok {
						if bucketName, ok := values["bucket"].(string); ok {
							if strings.Contains(bucketName, "vuln-securetransport-anonymous") {
								hasS3Bucket = true
							}
						}
					}
				}
			}
		}
	}

	// Check child modules (where our resources actually are)
	if childModules, ok := rootModule["child_modules"].([]interface{}); ok {
		for _, childModule := range childModules {
			if childModuleMap, ok := childModule.(map[string]interface{}); ok {
				if resources, ok := childModuleMap["resources"].([]interface{}); ok {
					for _, resource := range resources {
						if resourceMap, ok := resource.(map[string]interface{}); ok {
							resourceType, _ := resourceMap["type"].(string)
							
							if resourceType == "aws_lambda_function" {
								if values, ok := resourceMap["values"].(map[string]interface{}); ok {
									if functionName, ok := values["function_name"].(string); ok {
										if strings.Contains(functionName, "vuln-functionurlauthtype-none") {
											hasLambdaFunction = true
										}
									}
								}
							}

							if resourceType == "aws_s3_bucket" {
								if values, ok := resourceMap["values"].(map[string]interface{}); ok {
									if bucketName, ok := values["bucket"].(string); ok {
										if strings.Contains(bucketName, "vuln-securetransport-anonymous") {
											hasS3Bucket = true
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return hasLambdaFunction && hasS3Bucket
}

// formatStateInfo formats terraform state information for display
func formatStateInfo(moduleName string, state map[string]interface{}) string {
	var result strings.Builder
	result.WriteString(fmt.Sprintf("Module: %s\n", moduleName))

	values, ok := state["values"].(map[string]interface{})
	if !ok {
		result.WriteString("        No state information available")
		return result.String()
	}

	rootModule, ok := values["root_module"].(map[string]interface{})
	if !ok {
		result.WriteString("        No root module information available")
		return result.String()
	}

	resources, ok := rootModule["resources"].([]interface{})
	if !ok {
		result.WriteString("        No resources found")
		return result.String()
	}

	result.WriteString(fmt.Sprintf("        Resources found: %d\n", len(resources)))

	for _, resource := range resources {
		if resourceMap, ok := resource.(map[string]interface{}); ok {
			resourceType, _ := resourceMap["type"].(string)
			resourceAddress, _ := resourceMap["address"].(string)

			result.WriteString(fmt.Sprintf("        - %s (%s)\n", resourceAddress, resourceType))

			// Add specific details for key resources
			if values, ok := resourceMap["values"].(map[string]interface{}); ok {
				switch resourceType {
				case "aws_lambda_function":
					if functionName, ok := values["function_name"].(string); ok {
						result.WriteString(fmt.Sprintf("          Function Name: %s\n", functionName))
					}
				case "aws_instance":
					if tags, ok := values["tags"].(map[string]interface{}); ok {
						if name, ok := tags["Name"].(string); ok {
							result.WriteString(fmt.Sprintf("          Name: %s\n", name))
						}
					}
				}
			}
		}
	}

	return result.String()
}