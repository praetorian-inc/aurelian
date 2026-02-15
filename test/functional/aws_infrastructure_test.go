//go:build functional

package functional

import (
	"testing"
)

// TestAWSInfrastructureValidation validates that the test infrastructure is properly deployed
// Uses terraform-devops-engineer agent provided infrastructure validation helpers
func TestAWSInfrastructureValidation(t *testing.T) {
	creds := CheckCredentials() 
	if !creds.AWS {
		t.Skip("AWS credentials not available - skipping infrastructure validation")
	}

	// Test find-secrets infrastructure
	t.Run("find-secrets-infrastructure", func(t *testing.T) {
		if ValidateAWSInfrastructure("find-secrets") {
			t.Logf("✅ find-secrets infrastructure is properly deployed")
			
			// Get detailed status for logging
			if status, err := GetInfrastructureStatus("find-secrets"); err == nil {
				t.Logf("Infrastructure details: %s", status)
			}
		} else {
			t.Skip("find-secrets infrastructure not deployed - run terraform apply in Nebula-Cloud-Infrastructures/Testing Infrastructure/AWS/nebula-find-secrets")
		}
	})

	// Test list infrastructure  
	t.Run("list-infrastructure", func(t *testing.T) {
		if ValidateAWSInfrastructure("list") {
			t.Logf("✅ list infrastructure is properly deployed")
			
			// Get detailed status for logging
			if status, err := GetInfrastructureStatus("list"); err == nil {
				t.Logf("Infrastructure details: %s", status)
			}
		} else {
			t.Skip("list infrastructure not deployed - run terraform apply in Nebula-Cloud-Infrastructures/Testing Infrastructure/AWS/nebula-list")
		}
	})
}