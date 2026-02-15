package functional

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	// Azure test configuration
	AzureTestSubscription = "355e78a0-4c5e-4de3-9980-6a35cae86f01"
)

// TestAzureFunctionalCommands tests core Azure functional commands
func TestAzureFunctionalCommands(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping functional tests in short mode")
	}
	
	// Check if Azure credentials are available
	SkipIfCredentialsMissing(t, "azure", AzureTestSubscription)
	
	// Define test cases for Azure commands
	testCases := []struct {
		name         string
		category     string
		module       string
		args         []string
		timeout      time.Duration
		shouldFail   bool
		validateJSON bool
	}{
		// Azure Recon Commands
		{
			name:         "summary",
			category:     "recon",
			module:       "summary",
			args:         []string{},
			timeout:      3 * time.Minute,
			shouldFail:   false,
			validateJSON: true,
		},
		{
			name:         "list-all-quick",
			category:     "recon",
			module:       "list-all",
			args:         []string{"--limit", "10"},
			timeout:      5 * time.Minute,
			shouldFail:   false,
			validateJSON: true,
		},
		{
			name:         "public-resources",
			category:     "recon",
			module:       "public-resources",
			args:         []string{"--template", "storage_accounts_public"},
			timeout:      3 * time.Minute,
			shouldFail:   false,
			validateJSON: true,
		},
		{
			name:         "role-assignments-limited",
			category:     "recon",
			module:       "role-assignments",
			args:         []string{"--scope", "subscription", "--limit", "20"},
			timeout:      4 * time.Minute,
			shouldFail:   false,
			validateJSON: true,
		},
		
		// Azure Resource-specific tests
		{
			name:         "arg-scan-vm",
			category:     "recon",
			module:       "arg-scan",
			args:         []string{"--template", "virtual_machines_all", "--limit", "5"},
			timeout:      3 * time.Minute,
			shouldFail:   false,
			validateJSON: true,
		},
		{
			name:         "arg-scan-storage",
			category:     "recon",
			module:       "arg-scan",
			args:         []string{"--template", "storage_accounts_public", "--limit", "5"},
			timeout:      3 * time.Minute,
			shouldFail:   false,
			validateJSON: true,
		},
		
		// Error Cases
		{
			name:         "invalid-subscription",
			category:     "recon",
			module:       "summary",
			args:         []string{"--subscription-id", "00000000-0000-0000-0000-000000000000"},
			timeout:      1 * time.Minute,
			shouldFail:   true,
			validateJSON: false,
		},
		{
			name:         "invalid-template",
			category:     "recon",
			module:       "arg-scan",
			args:         []string{"--template", "nonexistent_template"},
			timeout:      1 * time.Minute,
			shouldFail:   true,
			validateJSON: false,
		},
	}
	
	// Run tests in parallel where appropriate
	for _, tc := range testCases {
		tc := tc // Capture loop variable
		t.Run(tc.name, func(t *testing.T) {
			// Don't run error cases in parallel to avoid credential issues
			if !tc.shouldFail {
				t.Parallel()
			}
			
			// Create command
			cmd := NewTestCommand("azure", tc.category, tc.module)
			if !tc.shouldFail {
				cmd.WithProfile(AzureTestSubscription)
			}
			cmd.WithArgs(tc.args...)
			cmd.WithTimeout(tc.timeout)
			
			if tc.shouldFail {
				cmd.ExpectFailure()
			}
			
			// Execute command
			result := RunNebulaCommand(t, cmd)
			
			// Validate result
			ValidateCommandResult(t, result)
			
			// Validate JSON output if expected
			if tc.validateJSON && !tc.shouldFail {
				ValidateJSONOutput(t, result)
			}
			
			// Additional validations based on command type
			switch tc.module {
			case "summary":
				if !tc.shouldFail {
					assert.NotEmpty(t, result.Stdout, "summary should produce output")
				}
			case "list-all":
				if !tc.shouldFail {
					assert.NotEmpty(t, result.Stdout, "list-all should produce output")
				}
			case "public-resources":
				if !tc.shouldFail {
					// May or may not find resources, but should not error
					assert.NotContains(t, result.Stderr, "panic", "public-resources should not panic")
				}
			case "role-assignments":
				if !tc.shouldFail {
					assert.NotEmpty(t, result.Stdout, "role-assignments should produce output")
				}
			case "arg-scan":
				if !tc.shouldFail {
					// Should produce some output
					assert.NotContains(t, result.Stderr, "panic", "arg-scan should not panic")
				}
			}
		})
	}
}

// TestAzureAdvancedCommands tests more complex Azure commands that may take longer
func TestAzureAdvancedCommands(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping advanced functional tests in short mode")
	}
	
	// Check if Azure credentials are available
	SkipIfCredentialsMissing(t, "azure", AzureTestSubscription)
	
	testCases := []struct {
		name         string
		category     string
		module       string
		args         []string
		timeout      time.Duration
		validateJSON bool
	}{
		{
			name:         "find-secrets-vm-limited",
			category:     "recon",
			module:       "find-secrets",
			args:         []string{"--resource-type", "vm", "--limit", "3"},
			timeout:      8 * time.Minute,
			validateJSON: true,
		},
		{
			name:         "find-secrets-storage-limited",
			category:     "recon",
			module:       "find-secrets",
			args:         []string{"--resource-type", "storage", "--limit", "3"},
			timeout:      8 * time.Minute,
			validateJSON: true,
		},
		{
			name:         "devops-secrets-quick",
			category:     "recon",
			module:       "devops-secrets",
			args:         []string{"--limit-orgs", "2", "--limit-projects", "3"},
			timeout:      5 * time.Minute,
			validateJSON: true,
		},
	}
	
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Create command
			cmd := NewTestCommand("azure", tc.category, tc.module).
				WithProfile(AzureTestSubscription).
				WithArgs(tc.args...).
				WithTimeout(tc.timeout)
			
			// Execute command
			result := RunNebulaCommand(t, cmd)
			
			// These commands may fail due to permissions or missing resources, so we check for non-panic errors
			if result.ExitCode != 0 {
				if result.HasErrors {
					// Log the error but don't fail the test if it's just permissions or missing resources
					for _, errorLine := range result.ErrorLines {
						if !isAzureExpectedError(errorLine) {
							t.Errorf("Command %s failed with unexpected error: %s", cmd.String(), errorLine)
						} else {
							t.Logf("Command %s failed with expected error: %s", cmd.String(), errorLine)
						}
					}
				}
			} else {
				// Command succeeded, validate JSON output
				if tc.validateJSON {
					ValidateJSONOutput(t, result)
				}
			}
		})
	}
}

// TestAzureHelp tests help commands for all Azure modules
func TestAzureHelp(t *testing.T) {
	testCases := []struct {
		name     string
		category string
		module   string
	}{
		{"azure-help", "", ""},
		{"azure-recon-help", "recon", ""},
		{"summary-help", "recon", "summary"},
		{"list-all-help", "recon", "list-all"},
		{"public-resources-help", "recon", "public-resources"},
		{"role-assignments-help", "recon", "role-assignments"},
		{"arg-scan-help", "recon", "arg-scan"},
		{"find-secrets-help", "recon", "find-secrets"},
		{"devops-secrets-help", "recon", "devops-secrets"},
	}
	
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			
			cmd := NewTestCommand("azure", tc.category, tc.module).
				WithArgs("--help").
				WithTimeout(30 * time.Second)
			
			result := RunNebulaCommand(t, cmd)
			
			// Help commands should always succeed
			assert.Equal(t, 0, result.ExitCode, "Help command should succeed")
			assert.NotEmpty(t, result.Stdout, "Help should produce output")
			assert.Contains(t, result.Stdout, "Usage:", "Help should contain usage information")
		})
	}
}

// TestAzureInvalidCommands tests invalid command combinations
func TestAzureInvalidCommands(t *testing.T) {
	testCases := []struct {
		name        string
		category    string
		module      string
		args        []string
		expectError bool
	}{
		// These will show help instead of failing, but should have error messages in output
		{"invalid-flag", "recon", "summary", []string{"--invalid-flag"}, true},
		{"invalid-template", "recon", "arg-scan", []string{"--template", "nonexistent_template"}, true},
	}
	
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			
			cmd := NewTestCommand("azure", tc.category, tc.module).
				WithArgs(tc.args...).
				WithTimeout(30 * time.Second)
			
			result := RunNebulaCommand(t, cmd)
			
			if tc.expectError {
				// Should have error messages even if exit code is 0 (due to help output)
				assert.True(t, result.HasErrors || result.ExitCode != 0, 
					"Invalid command should have errors or non-zero exit code")
			}
		})
	}
}

// TestAzureTemplates tests various Azure resource templates
func TestAzureTemplates(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping template tests in short mode")
	}
	
	// Check if Azure credentials are available
	SkipIfCredentialsMissing(t, "azure", AzureTestSubscription)
	
	templates := []string{
		"storage_accounts_public",
		"virtual_machines_public",
		"sql_servers_public",
		"app_services_public",
		"key_vault_public_access",
		"automation_accounts_all",
	}
	
	for _, template := range templates {
		template := template
		t.Run("template_"+template, func(t *testing.T) {
			t.Parallel()
			
			cmd := NewTestCommand("azure", "recon", "arg-scan").
				WithProfile(AzureTestSubscription).
				WithArgs("--template", template, "--limit", "5").
				WithTimeout(3 * time.Minute)
			
			result := RunNebulaCommand(t, cmd)
			
			// Template commands may not find resources but should not error
			if result.ExitCode != 0 && result.HasErrors {
				// Check if it's an expected error (no resources found, permissions, etc.)
				allExpectedErrors := true
				for _, errorLine := range result.ErrorLines {
					if !isAzureExpectedError(errorLine) {
						allExpectedErrors = false
						break
					}
				}
				
				if !allExpectedErrors {
					ValidateCommandResult(t, result)
				} else {
					t.Logf("Template %s completed with expected errors", template)
				}
			} else {
				// Command succeeded or failed with expected exit code
				if result.ExitCode == 0 {
					ValidateJSONOutput(t, result)
				}
			}
		})
	}
}

// isAzureExpectedError checks if an error line indicates an expected Azure error
func isAzureExpectedError(errorLine string) bool {
	expectedErrorKeywords := []string{
		"Forbidden",
		"Unauthorized",
		"AuthorizationFailed",
		"insufficient privileges",
		"access denied",
		"permission denied",
		"not found",
		"does not exist",
		"no resources found",
		"empty result",
		"subscription not found",
		"resource group not found",
		"InvalidResourceType",
		"ResourceNotFound",
		"SubscriptionNotFound",
		"InvalidAuthenticationToken",
		"ExpiredAuthenticationToken",
		"InvalidRequestContent",
		"MissingRegistration",
		"ServiceUnavailable",
		"TooManyRequests",
		"throttled",
		"rate limit",
		"quota exceeded",
	}
	
	lowerError := strings.ToLower(errorLine)
	for _, keyword := range expectedErrorKeywords {
		if strings.Contains(lowerError, strings.ToLower(keyword)) {
			return true
		}
	}
	
	return false
}

// TestAzureResourceSpecificCommands tests resource-specific functionality
func TestAzureResourceSpecificCommands(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping resource-specific tests in short mode")
	}
	
	// Check if Azure credentials are available
	SkipIfCredentialsMissing(t, "azure", AzureTestSubscription)
	
	testCases := []struct {
		name         string
		module       string
		args         []string
		timeout      time.Duration
		validateJSON bool
	}{
		{
			name:         "find-secrets-resource-vm",
			module:       "find-secrets-resource",
			args:         []string{"--resource-type", "Microsoft.Compute/virtualMachines", "--limit", "3"},
			timeout:      5 * time.Minute,
			validateJSON: true,
		},
		{
			name:         "find-secrets-resource-webapp",
			module:       "find-secrets-resource",
			args:         []string{"--resource-type", "Microsoft.Web/sites", "--limit", "3"},
			timeout:      5 * time.Minute,
			validateJSON: true,
		},
		{
			name:         "find-secrets-resource-storage",
			module:       "find-secrets-resource",
			args:         []string{"--resource-type", "Microsoft.Storage/storageAccounts", "--limit", "3"},
			timeout:      5 * time.Minute,
			validateJSON: true,
		},
	}
	
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cmd := NewTestCommand("azure", "recon", tc.module).
				WithProfile(AzureTestSubscription).
				WithArgs(tc.args...).
				WithTimeout(tc.timeout)
			
			result := RunNebulaCommand(t, cmd)
			
			// These commands may fail due to no resources or permissions
			if result.ExitCode != 0 && result.HasErrors {
				// Check if all errors are expected
				allExpectedErrors := true
				for _, errorLine := range result.ErrorLines {
					if !isAzureExpectedError(errorLine) {
						allExpectedErrors = false
						t.Errorf("Command %s failed with unexpected error: %s", cmd.String(), errorLine)
					}
				}
				
				if allExpectedErrors {
					t.Logf("Command %s completed with expected errors/no resources found", cmd.String())
				}
			} else if result.ExitCode == 0 {
				// Command succeeded
				if tc.validateJSON {
					ValidateJSONOutput(t, result)
				}
				t.Logf("Command %s completed successfully", cmd.String())
			}
		})
	}
}