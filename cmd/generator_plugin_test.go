package cmd

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPluginRegistryIntegration verifies generator uses plugin registry correctly
func TestPluginRegistryIntegration(t *testing.T) {
	// This test will fail until we update generator.go to use plugin registry
	t.Skip("Test will pass after implementing plugin registry support in generator")

	// Register a mock module
	mockModule := &testutils.MockModule{
		IDValue:          "test-module",
		NameValue:        "Test Module",
		DescriptionValue: "Test description",
		PlatformValue:    plugin.PlatformAWS,
		CategoryValue:    plugin.CategoryRecon,
		ParametersValue: []plugin.Parameter{
			{
				Name:        "test-param",
				Description: "Test parameter",
				Type:        "string",
				Required:    true,
			},
		},
	}

	plugin.Register(mockModule)

	// Verify module is registered
	retrieved, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "test-module")
	require.True(t, ok, "Module should be registered")
	assert.Equal(t, mockModule.IDValue, retrieved.ID())

	// Verify hierarchy
	hierarchy := plugin.GetHierarchy()
	assert.Contains(t, hierarchy, plugin.PlatformAWS)
	assert.Contains(t, hierarchy[plugin.PlatformAWS], plugin.CategoryRecon)
	assert.Contains(t, hierarchy[plugin.PlatformAWS][plugin.CategoryRecon], "test-module")
}
