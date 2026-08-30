package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLbBackendTakeoverModule_Metadata(t *testing.T) {
	m := &GCPLbBackendTakeoverModule{}
	assert.Equal(t, "lb-backend-takeover", m.ID())
	assert.Equal(t, "GCP LB Backend Bucket Takeover", m.Name())
	assert.Equal(t, plugin.PlatformGCP, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.Equal(t, "moderate", m.OpsecLevel())
	assert.NotEmpty(t, m.Description())
	assert.NotEmpty(t, m.References())
	assert.NotEmpty(t, m.Authors())
}

func TestLbBackendTakeoverModule_Parameters(t *testing.T) {
	m := &GCPLbBackendTakeoverModule{}
	params := m.Parameters()
	require.NotNil(t, params)
	_, ok := params.(*GCPLbBackendTakeoverConfig)
	assert.True(t, ok)
}

func TestLbBackendTakeoverModule_SupportedResourceTypes(t *testing.T) {
	m := &GCPLbBackendTakeoverModule{}
	types := m.SupportedResourceTypes()
	expected := []string{
		"cloudresourcemanager.googleapis.com/Organization",
		"cloudresourcemanager.googleapis.com/Folder",
		"cloudresourcemanager.googleapis.com/Project",
	}
	assert.ElementsMatch(t, expected, types)
}

func TestLbBackendTakeoverModule_Registration(t *testing.T) {
	mod, ok := plugin.Get(plugin.PlatformGCP, plugin.CategoryRecon, "lb-backend-takeover")
	require.True(t, ok, "module should be registered")
	assert.Equal(t, "lb-backend-takeover", mod.ID())
}
