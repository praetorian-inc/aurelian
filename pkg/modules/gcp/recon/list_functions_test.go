package recon

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGCPListFunctionsModule_Interface(t *testing.T) {
	m := &GCPListFunctionsModule{}

	// Verify it implements the Module interface
	var _ plugin.Module = m

	// Test metadata methods
	assert.Equal(t, "functions-list", m.ID())
	assert.Equal(t, "GCP List Functions", m.Name())
	assert.Equal(t, "List all Cloud Functions in a GCP project.", m.Description())
	assert.Equal(t, plugin.PlatformGCP, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.Equal(t, "moderate", m.OpsecLevel())
	assert.Equal(t, []string{"Praetorian"}, m.Authors())
	assert.Equal(t, []string{}, m.References())
}

func TestGCPListFunctionsModule_Parameters(t *testing.T) {
	m := &GCPListFunctionsModule{}
	params := m.Parameters()

	// Should have project parameter
	require.Greater(t, len(params), 0, "should have at least project parameter")

	// Verify project parameter exists
	var hasProject bool
	for _, p := range params {
		if p.Name == "project" {
			hasProject = true
			assert.True(t, p.Required, "project parameter should be required")
			assert.Equal(t, "string", p.Type)
			break
		}
	}
	assert.True(t, hasProject, "should have project parameter")
}

func TestGCPListFunctionsModule_Run_MissingProject(t *testing.T) {
	m := &GCPListFunctionsModule{}

	cfg := plugin.Config{
		Args:    map[string]any{},
		Context: context.Background(),
	}

	// Should fail without project parameter
	results, err := m.Run(cfg)
	require.Error(t, err)
	assert.Nil(t, results)
	assert.Contains(t, err.Error(), "project")
}
