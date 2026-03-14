package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSummaryModuleRegistration(t *testing.T) {
	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "summary")
	require.True(t, ok, "summary module should be registered")
	require.NotNil(t, mod)
}

func TestSummaryModuleMetadata(t *testing.T) {
	m := &AWSSummaryModule{}
	assert.Equal(t, "summary", m.ID())
	assert.Equal(t, "AWS Summary", m.Name())
	assert.Equal(t, plugin.PlatformAWS, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.Equal(t, "moderate", m.OpsecLevel())
	assert.NotEmpty(t, m.Description())
	assert.Contains(t, m.Description(), "Cost Explorer")
}

func TestSummaryModuleParameters(t *testing.T) {
	m := &AWSSummaryModule{}
	params, err := plugin.ParametersFrom(m.Parameters())
	require.NoError(t, err)

	paramNames := make(map[string]bool)
	for _, p := range params {
		paramNames[p.Name] = true
	}

	assert.True(t, paramNames["profile"], "should have profile param")
	assert.True(t, paramNames["days"], "should have days param")
}

func TestCleanServiceName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Amazon EC2", "EC2"},
		{"AWS Lambda", "Lambda"},
		{"Amazon Simple Storage Service", "Simple Storage Service"},
		{"CloudWatch", "CloudWatch"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, cleanServiceName(tt.input))
	}
}
