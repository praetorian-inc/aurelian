package analyze

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpandPermissionsModuleRegistration(t *testing.T) {
	mod, ok := plugin.Get(plugin.PlatformGCP, plugin.CategoryAnalyze, "expand-permissions")
	require.True(t, ok, "expand-permissions module should be registered")
	require.NotNil(t, mod)
}

func TestExpandPermissionsModuleMetadata(t *testing.T) {
	m := &ExpandPermissionsModule{}
	assert.Equal(t, "expand-permissions", m.ID())
	assert.Equal(t, "GCP Expand Permissions", m.Name())
	assert.Equal(t, plugin.PlatformGCP, m.Platform())
	assert.Equal(t, plugin.CategoryAnalyze, m.Category())
	assert.Equal(t, "safe", m.OpsecLevel())
	assert.NotEmpty(t, m.Description())
	assert.Nil(t, m.SupportedResourceTypes())
}

func TestExpandPermissionsModuleParameters(t *testing.T) {
	m := &ExpandPermissionsModule{}
	params, err := plugin.ParametersFrom(m.Parameters())
	require.NoError(t, err)

	paramNames := make(map[string]bool)
	for _, p := range params {
		paramNames[p.Name] = true
	}

	assert.True(t, paramNames["roles"], "should have roles param")
	assert.True(t, paramNames["creds-file"], "should have creds-file param")
	assert.True(t, paramNames["quota-project"], "should have quota-project param")
}
