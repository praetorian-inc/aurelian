package enrichment

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAzureEnricherForwardsWithoutEnrichers(t *testing.T) {
	plugin.ResetAzureEnricherRegistry()

	enricher := NewAzureEnricher(nil)
	resource := output.AzureResource{
		ResourceType: "Microsoft.Compute/virtualMachines",
		ResourceID:   "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1",
		Properties:   map[string]any{"vmSize": "Standard_B1ls"},
	}

	out := pipeline.New[output.AzureResource]()
	go func() {
		defer out.Close()
		err := enricher.Enrich(resource, out)
		assert.NoError(t, err)
	}()

	results, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "Standard_B1ls", results[0].Properties["vmSize"])
}

func TestAzureEnricherRunsRegisteredEnrichers(t *testing.T) {
	plugin.ResetAzureEnricherRegistry()

	plugin.RegisterAzureEnricher("Microsoft.Web/sites", func(cfg plugin.AzureEnricherConfig, r *output.AzureResource) error {
		r.Properties["enriched"] = true
		return nil
	})

	enricher := NewAzureEnricher(nil)
	resource := output.AzureResource{
		ResourceType: "Microsoft.Web/sites",
		ResourceID:   "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Web/sites/myapp",
		Properties:   make(map[string]any),
	}

	out := pipeline.New[output.AzureResource]()
	go func() {
		defer out.Close()
		err := enricher.Enrich(resource, out)
		assert.NoError(t, err)
	}()

	results, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, true, results[0].Properties["enriched"])
}

func TestAzureEnricherContinuesOnError(t *testing.T) {
	plugin.ResetAzureEnricherRegistry()

	plugin.RegisterAzureEnricher("Microsoft.Web/sites", func(cfg plugin.AzureEnricherConfig, r *output.AzureResource) error {
		return assert.AnError
	})
	plugin.RegisterAzureEnricher("Microsoft.Web/sites", func(cfg plugin.AzureEnricherConfig, r *output.AzureResource) error {
		r.Properties["secondRan"] = true
		return nil
	})

	enricher := NewAzureEnricher(nil)
	resource := output.AzureResource{
		ResourceType: "Microsoft.Web/sites",
		ResourceID:   "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Web/sites/myapp",
		Properties:   make(map[string]any),
	}

	out := pipeline.New[output.AzureResource]()
	go func() {
		defer out.Close()
		err := enricher.Enrich(resource, out)
		assert.NoError(t, err)
	}()

	results, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, true, results[0].Properties["secondRan"])
}
