package plugin_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterAzureEnricher(t *testing.T) {
	plugin.ResetAzureEnricherRegistry()

	called := false
	enricher := func(cfg plugin.AzureEnricherConfig, r *output.AzureResource) error {
		called = true
		r.Properties["TestProperty"] = "value"
		return nil
	}

	plugin.RegisterAzureEnricher("Microsoft.Web/sites", enricher)

	enrichers := plugin.GetAzureEnrichers("Microsoft.Web/sites")
	require.Len(t, enrichers, 1)

	resource := &output.AzureResource{
		ResourceType: "Microsoft.Web/sites",
		Properties:   make(map[string]any),
	}
	cfg := plugin.AzureEnricherConfig{
		Context:    context.Background(),
		Credential: nil,
	}

	err := enrichers[0](cfg, resource)
	assert.NoError(t, err)
	assert.True(t, called)
	assert.Equal(t, "value", resource.Properties["TestProperty"])
}

func TestMultipleAzureEnrichersPerType(t *testing.T) {
	plugin.ResetAzureEnricherRegistry()

	enricher1 := func(cfg plugin.AzureEnricherConfig, r *output.AzureResource) error {
		r.Properties["Enricher1"] = "ran"
		return nil
	}
	enricher2 := func(cfg plugin.AzureEnricherConfig, r *output.AzureResource) error {
		r.Properties["Enricher2"] = "ran"
		return nil
	}

	plugin.RegisterAzureEnricher("Microsoft.Web/sites", enricher1)
	plugin.RegisterAzureEnricher("Microsoft.Web/sites", enricher2)

	enrichers := plugin.GetAzureEnrichers("Microsoft.Web/sites")
	require.Len(t, enrichers, 2)

	resource := &output.AzureResource{
		ResourceType: "Microsoft.Web/sites",
		Properties:   make(map[string]any),
	}
	cfg := plugin.AzureEnricherConfig{Context: context.Background()}

	for _, enrich := range enrichers {
		err := enrich(cfg, resource)
		assert.NoError(t, err)
	}

	assert.Equal(t, "ran", resource.Properties["Enricher1"])
	assert.Equal(t, "ran", resource.Properties["Enricher2"])
}

func TestAzureEnricherErrorHandling(t *testing.T) {
	plugin.ResetAzureEnricherRegistry()

	enricher := func(cfg plugin.AzureEnricherConfig, r *output.AzureResource) error {
		return fmt.Errorf("enrichment failed")
	}

	plugin.RegisterAzureEnricher("Microsoft.CognitiveServices/accounts", enricher)

	resource := &output.AzureResource{
		ResourceType: "Microsoft.CognitiveServices/accounts",
		Properties:   make(map[string]any),
	}
	cfg := plugin.AzureEnricherConfig{Context: context.Background()}

	enrichers := plugin.GetAzureEnrichers("Microsoft.CognitiveServices/accounts")
	err := enrichers[0](cfg, resource)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "enrichment failed")
}

func TestGetAzureEnrichersUnknownType(t *testing.T) {
	plugin.ResetAzureEnricherRegistry()

	enricher := func(cfg plugin.AzureEnricherConfig, r *output.AzureResource) error {
		return nil
	}
	plugin.RegisterAzureEnricher("Microsoft.Web/sites", enricher)

	enrichers := plugin.GetAzureEnrichers("Microsoft.Compute/virtualMachines")

	assert.NotNil(t, enrichers)
	assert.Len(t, enrichers, 0)
}

func TestAzureEnricherRegistryConcurrency(t *testing.T) {
	plugin.ResetAzureEnricherRegistry()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			enricher := func(cfg plugin.AzureEnricherConfig, r *output.AzureResource) error {
				r.Properties[fmt.Sprintf("Enricher%d", id)] = "ran"
				return nil
			}
			plugin.RegisterAzureEnricher("Microsoft.Web/sites", enricher)
		}(i)
	}
	wg.Wait()

	enrichers := plugin.GetAzureEnrichers("Microsoft.Web/sites")
	assert.Len(t, enrichers, 100)
}
