package plugin

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/templates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAzureEnricherRegistration(t *testing.T) {
	ResetAzureEnricherRegistry()
	defer ResetAzureEnricherRegistry()

	called := false
	fn := func(cfg AzureEnricherConfig, result *templates.ARGQueryResult) ([]AzureEnrichmentCommand, error) {
		called = true
		return []AzureEnrichmentCommand{{Description: "test"}}, nil
	}

	RegisterAzureEnricher("storage_accounts_public_access", fn)

	enrichers := GetAzureEnrichers("storage_accounts_public_access")
	require.Len(t, enrichers, 1)

	cmds, err := enrichers[0](AzureEnricherConfig{Context: context.Background()}, &templates.ARGQueryResult{})
	require.NoError(t, err)
	assert.True(t, called)
	assert.Len(t, cmds, 1)
	assert.Equal(t, "test", cmds[0].Description)
}

func TestAzureEnricherRegistryEmpty(t *testing.T) {
	ResetAzureEnricherRegistry()
	defer ResetAzureEnricherRegistry()

	enrichers := GetAzureEnrichers("nonexistent_template")
	assert.Empty(t, enrichers)
}
