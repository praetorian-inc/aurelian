package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicResourcesSingleModule_Metadata(t *testing.T) {
	m := &PublicResourcesSingleModule{}

	assert.Equal(t, "public-resources-single", m.ID())
	assert.Equal(t, "AWS Public Resources Single", m.Name())
	assert.Contains(t, m.Description(), "public AWS resources")
	assert.Equal(t, plugin.PlatformAWS, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.Equal(t, "moderate", m.OpsecLevel())
	assert.Equal(t, []string{"Praetorian"}, m.Authors())
}

func TestPublicResourcesSingleModule_Parameters(t *testing.T) {
	m := &PublicResourcesSingleModule{}
	params := m.Parameters()

	// Should have resource-arn parameter
	require.GreaterOrEqual(t, len(params), 1)

	paramNames := make(map[string]bool)
	for _, p := range params {
		paramNames[p.Name] = true
	}

	assert.True(t, paramNames["resource-arn"], "should have resource-arn parameter")
}

func TestPublicResourcesSingleModule_Registration(t *testing.T) {
	// Verify module is registered in plugin registry
	m, exists := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "public-resources-single")
	require.True(t, exists, "module should be registered")
	require.NotNil(t, m, "module should not be nil")

	prModule, ok := m.(*PublicResourcesSingleModule)
	require.True(t, ok, "should be PublicResourcesSingleModule type")
	assert.Equal(t, "public-resources-single", prModule.ID())
}
