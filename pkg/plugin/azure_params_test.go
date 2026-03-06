package plugin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAzureCommonRecon_ParameterBinding(t *testing.T) {
	cfg := Config{
		Args: map[string]any{
			"subscription-ids": []string{"sub-123", "sub-456"},
		},
	}

	var params AzureCommonRecon
	err := Bind(cfg, &params)
	require.NoError(t, err)
	assert.Equal(t, []string{"sub-123", "sub-456"}, params.SubscriptionIDs)
}

func TestAzureCommonRecon_ParameterTags(t *testing.T) {
	p, err := ParametersFrom(&AzureCommonRecon{})
	require.NoError(t, err)
	require.NotEmpty(t, p)

	found := false
	for _, param := range p {
		if param.Name == "subscription-ids" {
			found = true
			assert.False(t, param.Required)
			assert.Equal(t, []string{"all"}, param.Default)
		}
	}
	assert.True(t, found, "subscription-id parameter not found")
}

func TestAzureCommonRecon_DefaultSubscriptionID(t *testing.T) {
	cfg := Config{
		Args: map[string]any{},
	}

	var params AzureCommonRecon
	err := Bind(cfg, &params)
	require.NoError(t, err)
	assert.Equal(t, []string{"all"}, params.SubscriptionIDs)
}
