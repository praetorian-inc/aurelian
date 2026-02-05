// +build integration

package cmd

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// TestMCPServerCanAccessRegistry verifies the MCP server can access the plugin registry
func TestMCPServerCanAccessRegistry(t *testing.T) {
	// This test verifies that when the MCP server imports the plugin package,
	// modules have registered themselves via init()

	hierarchy := plugin.GetHierarchy()

	if len(hierarchy) == 0 {
		t.Fatal("Expected plugin registry to have registered modules, but hierarchy is empty")
	}

	t.Logf("Plugin registry has %d platforms", len(hierarchy))

	totalModules := 0
	for platform, categories := range hierarchy {
		for category, moduleIDs := range categories {
			t.Logf("Platform: %s, Category: %s, Modules: %d", platform, category, len(moduleIDs))
			totalModules += len(moduleIDs)
		}
	}

	if totalModules == 0 {
		t.Fatal("Expected at least one registered module")
	}

	t.Logf("Total registered modules: %d", totalModules)
}
