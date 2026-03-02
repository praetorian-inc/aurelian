package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAzureListAllModule_Registration(t *testing.T) {
	mod, ok := plugin.Get(plugin.PlatformAzure, plugin.CategoryRecon, "list-all")
	require.True(t, ok, "module should be registered")
	assert.Equal(t, "list-all", mod.ID())
	assert.Equal(t, plugin.PlatformAzure, mod.Platform())
	assert.Equal(t, plugin.CategoryRecon, mod.Category())
	assert.Equal(t, "stealth", mod.OpsecLevel())
}

func TestAzureListAllModule_Parameters(t *testing.T) {
	mod, ok := plugin.Get(plugin.PlatformAzure, plugin.CategoryRecon, "list-all")
	require.True(t, ok)

	params := mod.Parameters()
	require.NotNil(t, params)

	p, err := plugin.ParametersFrom(params)
	require.NoError(t, err)

	names := make(map[string]bool)
	for _, param := range p {
		names[param.Name] = true
	}
	assert.True(t, names["subscription-id"], "should have subscription-id parameter")
}
