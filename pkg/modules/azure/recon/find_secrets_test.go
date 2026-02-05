package recon

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func TestAzureFindSecretsModule_Metadata(t *testing.T) {
	module := &AzureFindSecretsModule{}

	// Test ID
	if got := module.ID(); got != "find-secrets" {
		t.Errorf("ID() = %v, want find-secrets", got)
	}

	// Test Name
	if got := module.Name(); got != "Azure Find Secrets" {
		t.Errorf("Name() = %v, want Azure Find Secrets", got)
	}

	// Test Platform
	if got := module.Platform(); got != plugin.PlatformAzure {
		t.Errorf("Platform() = %v, want %v", got, plugin.PlatformAzure)
	}

	// Test Category
	if got := module.Category(); got != plugin.CategoryRecon {
		t.Errorf("Category() = %v, want %v", got, plugin.CategoryRecon)
	}

	// Test OpsecLevel
	if got := module.OpsecLevel(); got != "moderate" {
		t.Errorf("OpsecLevel() = %v, want moderate", got)
	}

	// Test Authors
	authors := module.Authors()
	if len(authors) != 1 || authors[0] != "Praetorian" {
		t.Errorf("Authors() = %v, want [Praetorian]", authors)
	}

	// Test References
	refs := module.References()
	if len(refs) != 2 {
		t.Errorf("References() length = %v, want 2", len(refs))
	}
}

func TestAzureFindSecretsModule_Parameters(t *testing.T) {
	module := &AzureFindSecretsModule{}
	params := module.Parameters()

	expectedParams := map[string]bool{
		"subscription-id":  true,
		"resource-types":   true,
		"category":         true,
		"module-name":      true,
		"continue-piping":  true,
	}

	if len(params) != len(expectedParams) {
		t.Errorf("Parameters() length = %v, want %v", len(params), len(expectedParams))
	}

	for _, param := range params {
		if !expectedParams[param.Name] {
			t.Errorf("Unexpected parameter: %s", param.Name)
		}
	}
}

func TestAzureFindSecretsModule_Run(t *testing.T) {
	module := &AzureFindSecretsModule{}

	cfg := plugin.Config{
		Context: context.Background(),
		Args: map[string]any{
			"subscription-id": "test-subscription",
			"resource-types":  "VirtualMachine,WebApp",
			"category":        "secrets",
			"module-name":     "find-secrets",
		},
		Verbose: true,
	}

	results, err := module.Run(cfg)
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("Run() returned no results")
	}

	// Verify the placeholder result structure
	result := results[0]
	if result.Data == nil {
		t.Error("Result.Data is nil")
	}

	if result.Metadata == nil {
		t.Error("Result.Metadata is nil")
	}

	// Check metadata contains expected fields
	metadata := result.Metadata
	if platform, ok := metadata["platform"].(string); !ok || platform != "azure" {
		t.Errorf("Metadata platform = %v, want azure", metadata["platform"])
	}
}

func TestAzureFindSecretsModule_RunWithDefaults(t *testing.T) {
	module := &AzureFindSecretsModule{}

	cfg := plugin.Config{
		Context: context.Background(),
		Args:    map[string]any{},
		Verbose: false,
	}

	results, err := module.Run(cfg)
	if err != nil {
		t.Fatalf("Run() with defaults returned error: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("Run() with defaults returned no results")
	}
}
