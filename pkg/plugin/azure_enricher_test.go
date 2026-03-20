package plugin

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/templates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterAndGetAzureEnricher(t *testing.T) {
	defer ResetAzureEnricherRegistry()

	called := false
	fn := func(_ AzureEnricherConfig, result *templates.ARGQueryResult) error {
		called = true
		result.Properties["test"] = true
		return nil
	}

	RegisterAzureEnricher("microsoft.web/sites", fn)
	enrichers := GetAzureEnrichers("microsoft.web/sites")

	require.Len(t, enrichers, 1)
	r := &templates.ARGQueryResult{Properties: map[string]any{}}
	err := enrichers[0](AzureEnricherConfig{Context: context.Background()}, r)
	assert.NoError(t, err)
	assert.True(t, called)
	assert.Equal(t, true, r.Properties["test"])
}

func TestGetAzureEnrichers_Unregistered(t *testing.T) {
	defer ResetAzureEnricherRegistry()
	assert.Empty(t, GetAzureEnrichers("nonexistent"))
}

func TestRegisterAzureEnricher_MultiplePerType(t *testing.T) {
	defer ResetAzureEnricherRegistry()

	RegisterAzureEnricher("microsoft.web/sites", func(_ AzureEnricherConfig, _ *templates.ARGQueryResult) error { return nil })
	RegisterAzureEnricher("microsoft.web/sites", func(_ AzureEnricherConfig, _ *templates.ARGQueryResult) error { return nil })

	assert.Len(t, GetAzureEnrichers("microsoft.web/sites"), 2)
}

func TestResetAzureEnricherRegistry(t *testing.T) {
	RegisterAzureEnricher("microsoft.web/sites", func(_ AzureEnricherConfig, _ *templates.ARGQueryResult) error { return nil })
	ResetAzureEnricherRegistry()
	assert.Empty(t, GetAzureEnrichers("microsoft.web/sites"))
}
