package analyze

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccessKeyToAccountIDModuleRegistration(t *testing.T) {
	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryAnalyze, "access-key-to-account-id")
	require.True(t, ok, "access-key-to-account-id module should be registered")
	require.NotNil(t, mod)
}

func TestAccessKeyToAccountIDModuleMetadata(t *testing.T) {
	m := &AccessKeyToAccountIDModule{}
	assert.Equal(t, "access-key-to-account-id", m.ID())
	assert.Equal(t, "AWS Access Key to Account ID", m.Name())
	assert.Equal(t, plugin.PlatformAWS, m.Platform())
	assert.Equal(t, plugin.CategoryAnalyze, m.Category())
	assert.Equal(t, "safe", m.OpsecLevel())
	assert.NotEmpty(t, m.Description())
	assert.Nil(t, m.SupportedResourceTypes())
}

func TestAccessKeyToAccountIDModuleParameters(t *testing.T) {
	m := &AccessKeyToAccountIDModule{}
	params, err := plugin.ParametersFrom(m.Parameters())
	require.NoError(t, err)

	paramNames := make(map[string]bool)
	for _, p := range params {
		paramNames[p.Name] = true
	}

	assert.True(t, paramNames["access-key-id"], "should have access-key-id param")
}

func TestAccountIDFromAccessKey(t *testing.T) {
	tests := []struct {
		name      string
		keyID     string
		wantAcct  string
		wantError bool
	}{
		{
			name:     "AKIA example key",
			keyID:    "AKIAIOSFODNN7EXAMPLE",
			wantAcct: "581039954779",
		},
		{
			name:     "AKIA real key",
			keyID:    "AKIAV7S32T2OSBFJQOIY",
			wantAcct: "411435703965",
		},
		{
			name:     "ASIA temporary key",
			keyID:    "ASIAY34FZKBOKMUTVV7A",
			wantAcct: "609629065308",
		},
		{
			name:      "too short after prefix",
			keyID:     "AKIAA",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := accountIDFromAccessKey(tt.keyID)
			if tt.wantError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantAcct, got)
		})
	}
}
