package plugin_test

import (
	"fmt"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/testutils"
)

func TestRegister(t *testing.T) {
	// Create a fresh registry for testing
	plugin.ResetRegistry()

	module := &testutils.MockModule{
		IDValue:          "test-module",
		NameValue:        "Test Module",
		DescriptionValue: "A test module",
		PlatformValue:    plugin.PlatformAWS,
		CategoryValue:    plugin.CategoryRecon,
		OpsecLevelValue:  "stealth",
		AuthorsValue:     []string{"Test Author"},
		ReferencesValue:  []string{"https://example.com"},
		ParametersValue:  []plugin.Parameter{},
	}

	plugin.Register(module)

	// Verify registration
	if plugin.Count() != 1 {
		t.Errorf("Expected 1 registered module, got %d", plugin.Count())
	}

	// Verify retrieval
	retrieved, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "test-module")
	if !ok {
		t.Fatal("Failed to retrieve registered module")
	}

	if retrieved.ID() != "test-module" {
		t.Errorf("Expected module ID 'test-module', got '%s'", retrieved.ID())
	}
}

func TestRegisterDuplicate(t *testing.T) {
	// Create a fresh registry for testing
	plugin.ResetRegistry()

	module := &testutils.MockModule{
		IDValue:       "duplicate",
		PlatformValue: plugin.PlatformAWS,
		CategoryValue: plugin.CategoryRecon,
	}

	plugin.Register(module)

	// Attempt to register duplicate should panic
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic when registering duplicate module")
		}
	}()

	plugin.Register(module)
}

func TestGetNonExistent(t *testing.T) {
	// Create a fresh registry for testing
	plugin.ResetRegistry()

	_, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "nonexistent")
	if ok {
		t.Error("Expected false when retrieving nonexistent module")
	}
}

func TestGetHierarchy(t *testing.T) {
	// Create a fresh registry for testing
	plugin.ResetRegistry()

	// Register multiple modules
	modules := []*testutils.MockModule{
		{IDValue: "aws-recon-1", PlatformValue: plugin.PlatformAWS, CategoryValue: plugin.CategoryRecon},
		{IDValue: "aws-recon-2", PlatformValue: plugin.PlatformAWS, CategoryValue: plugin.CategoryRecon},
		{IDValue: "aws-analyze-1", PlatformValue: plugin.PlatformAWS, CategoryValue: plugin.CategoryAnalyze},
		{IDValue: "azure-recon-1", PlatformValue: plugin.PlatformAzure, CategoryValue: plugin.CategoryRecon},
	}

	for _, m := range modules {
		plugin.Register(m)
	}

	hierarchy := plugin.GetHierarchy()

	// Verify AWS recon has 2 modules
	awsRecon := hierarchy[plugin.PlatformAWS][plugin.CategoryRecon]
	if len(awsRecon) != 2 {
		t.Errorf("Expected 2 AWS recon modules, got %d", len(awsRecon))
	}

	// Verify AWS analyze has 1 module
	awsAnalyze := hierarchy[plugin.PlatformAWS][plugin.CategoryAnalyze]
	if len(awsAnalyze) != 1 {
		t.Errorf("Expected 1 AWS analyze module, got %d", len(awsAnalyze))
	}

	// Verify Azure recon has 1 module
	azureRecon := hierarchy[plugin.PlatformAzure][plugin.CategoryRecon]
	if len(azureRecon) != 1 {
		t.Errorf("Expected 1 Azure recon module, got %d", len(azureRecon))
	}

	// Verify total count
	if plugin.Count() != 4 {
		t.Errorf("Expected 4 total modules, got %d", plugin.Count())
	}
}

func TestCount(t *testing.T) {
	// Create a fresh registry for testing
	plugin.ResetRegistry()

	if plugin.Count() != 0 {
		t.Errorf("Expected 0 modules in empty registry, got %d", plugin.Count())
	}

	plugin.Register(&testutils.MockModule{IDValue: "test1", PlatformValue: plugin.PlatformAWS, CategoryValue: plugin.CategoryRecon})
	if plugin.Count() != 1 {
		t.Errorf("Expected 1 module after first registration, got %d", plugin.Count())
	}

	plugin.Register(&testutils.MockModule{IDValue: "test2", PlatformValue: plugin.PlatformAWS, CategoryValue: plugin.CategoryRecon})
	if plugin.Count() != 2 {
		t.Errorf("Expected 2 modules after second registration, got %d", plugin.Count())
	}
}

func TestThreadSafety(t *testing.T) {
	// Create a fresh registry for testing
	plugin.ResetRegistry()

	// Test concurrent registration
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			module := &testutils.MockModule{
				IDValue:       fmt.Sprintf("concurrent-%d", id),
				PlatformValue: plugin.PlatformAWS,
				CategoryValue: plugin.CategoryRecon,
			}
			plugin.Register(module)
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	if plugin.Count() != 10 {
		t.Errorf("Expected 10 modules after concurrent registration, got %d", plugin.Count())
	}
}
