package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func TestDevOpsSecretsModuleModule(t *testing.T) {
	// Test that the module is properly defined
	module := &DevOpsSecretsModule{}

	// Verify it implements plugin.Module
	var _ plugin.Module = module

	// Check required properties using plugin.Module interface methods
	if module.ID() != "devops-secrets" {
		t.Errorf("Expected id 'devops-secrets', got %v", module.ID())
	}

	if module.Platform() != plugin.PlatformAzure {
		t.Errorf("Expected platform 'azure', got %v", module.Platform())
	}

	if module.OpsecLevel() != "moderate" {
		t.Errorf("Expected opsec_level 'moderate', got %v", module.OpsecLevel())
	}

	// Check authors
	authors := module.Authors()
	if len(authors) == 0 {
		t.Error("Module authors not properly set")
	}

	if authors[0] != "Praetorian" {
		t.Errorf("Expected first author 'Praetorian', got %s", authors[0])
	}
}
