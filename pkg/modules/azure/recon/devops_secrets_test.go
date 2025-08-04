package recon

import (
	"testing"
)

func TestAzureDevOpsSecretsModule(t *testing.T) {
	// Test that the module is properly defined
	if AzureDevOpsSecrets == nil {
		t.Fatal("AzureDevOpsSecrets module is nil")
	}

	// Test metadata
	metadata := AzureDevOpsSecrets.Metadata()
	if metadata == nil {
		t.Fatal("Module metadata is nil")
	}

	// Check required properties
	props := metadata.Properties()
	if props["id"] != "devops-secrets" {
		t.Errorf("Expected id 'devops-secrets', got %v", props["id"])
	}

	if props["platform"] != "azure" {
		t.Errorf("Expected platform 'azure', got %v", props["platform"])
	}

	if props["opsec_level"] != "moderate" {
		t.Errorf("Expected opsec_level 'moderate', got %v", props["opsec_level"])
	}

	// Check authors
	authors, ok := props["authors"].([]string)
	if !ok || len(authors) == 0 {
		t.Error("Module authors not properly set")
	}

	if authors[0] != "Praetorian" {
		t.Errorf("Expected first author 'Praetorian', got %s", authors[0])
	}
}