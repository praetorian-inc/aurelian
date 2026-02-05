package cmd

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// TestMCPServerPluginRegistry verifies that the MCP server can iterate
// over the plugin registry and find registered modules
func TestMCPServerPluginRegistry(t *testing.T) {
	// Get hierarchy from new plugin registry
	hierarchy := plugin.GetHierarchy()

	// Should have at least one platform
	if len(hierarchy) == 0 {
		t.Fatal("Expected plugin registry to have registered modules")
	}

	// Count total modules across all platforms/categories
	totalModules := 0
	for platform, categories := range hierarchy {
		for category, moduleIDs := range categories {
			totalModules += len(moduleIDs)

			// Verify we can retrieve each module by ID
			for _, moduleID := range moduleIDs {
				mod, ok := plugin.Get(platform, category, moduleID)
				if !ok {
					t.Errorf("Failed to retrieve module: %s/%s/%s", platform, category, moduleID)
					continue
				}

				// Verify module has required metadata
				if mod.ID() != moduleID {
					t.Errorf("Module ID mismatch: expected %s, got %s", moduleID, mod.ID())
				}
				if mod.Name() == "" {
					t.Errorf("Module %s has empty name", moduleID)
				}
				if mod.Description() == "" {
					t.Errorf("Module %s has empty description", moduleID)
				}
			}
		}
	}

	if totalModules == 0 {
		t.Fatal("Expected at least one registered module")
	}

	t.Logf("Successfully validated %d modules from plugin registry", totalModules)
}

// TestMCPToolConversion verifies that we can convert a plugin.Module
// to an MCP tool (this tests the adapter function we need to create)
func TestMCPToolConversion(t *testing.T) {
	// Get first available module from registry
	hierarchy := plugin.GetHierarchy()
	if len(hierarchy) == 0 {
		t.Skip("No modules registered")
	}

	var testModule plugin.Module
	for platform, categories := range hierarchy {
		for category, moduleIDs := range categories {
			if len(moduleIDs) > 0 {
				mod, ok := plugin.Get(platform, category, moduleIDs[0])
				if !ok {
					t.Fatal("Failed to get module for testing")
				}
				testModule = mod
				break
			}
		}
		if testModule != nil {
			break
		}
	}

	if testModule == nil {
		t.Skip("No modules available for testing")
	}

	// Convert to MCP tool
	tool := pluginToMCPTool(testModule)

	// Verify tool has expected properties
	if tool.Name == "" {
		t.Error("MCP tool has empty name")
	}
	if tool.Description == "" {
		t.Error("MCP tool has empty description")
	}
	if tool.InputSchema.Properties == nil {
		t.Error("MCP tool has nil properties")
	}

	t.Logf("Successfully converted module %s to MCP tool", testModule.ID())
}
