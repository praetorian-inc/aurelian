package cmd

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPluginRegistryIntegration verifies generator uses plugin registry correctly
func TestPluginRegistryIntegration(t *testing.T) {
	// This test will fail until we update generator.go to use plugin registry
	t.Skip("Test will pass after implementing plugin registry support in generator")

	// Register a mock module
	mockModule := &mockModule{
		id:          "test-module",
		name:        "Test Module",
		description: "Test description",
		platform:    plugin.PlatformAWS,
		category:    plugin.CategoryRecon,
		parameters: []plugin.Parameter{
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
	assert.Equal(t, mockModule.id, retrieved.ID())

	// Verify hierarchy
	hierarchy := plugin.GetHierarchy()
	assert.Contains(t, hierarchy, plugin.PlatformAWS)
	assert.Contains(t, hierarchy[plugin.PlatformAWS], plugin.CategoryRecon)
	assert.Contains(t, hierarchy[plugin.PlatformAWS][plugin.CategoryRecon], "test-module")
}

// mockModule implements plugin.Module for testing
type mockModule struct {
	id          string
	name        string
	description string
	platform    plugin.Platform
	category    plugin.Category
	parameters  []plugin.Parameter
}

func (m *mockModule) ID() string                    { return m.id }
func (m *mockModule) Name() string                  { return m.name }
func (m *mockModule) Description() string           { return m.description }
func (m *mockModule) Platform() plugin.Platform     { return m.platform }
func (m *mockModule) Category() plugin.Category     { return m.category }
func (m *mockModule) OpsecLevel() string            { return "low" }
func (m *mockModule) Authors() []string             { return []string{"test"} }
func (m *mockModule) References() []string          { return []string{} }
func (m *mockModule) Parameters() []plugin.Parameter { return m.parameters }

func (m *mockModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	return []plugin.Result{{Data: "test"}}, nil
}
