package plugin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAzureCommonRecon_ParameterBinding(t *testing.T) {
	cfg := Config{
		Args: map[string]any{
			"subscription-id": []string{"sub-123", "sub-456"},
		},
	}

	var params AzureCommonRecon
	err := Bind(cfg, &params)
	require.NoError(t, err)
	assert.Equal(t, []string{"sub-123", "sub-456"}, params.SubscriptionID)
}

func TestAzureCommonRecon_ParameterTags(t *testing.T) {
	p, err := ParametersFrom(&AzureCommonRecon{})
	require.NoError(t, err)
	require.NotEmpty(t, p)

	found := false
	for _, param := range p {
		if param.Name == "subscription-id" {
			found = true
			assert.True(t, param.Required)
		}
	}
	assert.True(t, found, "subscription-id parameter not found")
}
