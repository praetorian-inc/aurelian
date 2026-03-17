package enrichment

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnrich_UnregisteredType_PassesThrough(t *testing.T) {
	defer plugin.ResetAzureEnricherRegistry()

	e := NewAzureEnricher(context.Background(), nil, 120*time.Second)
	result := templates.ARGQueryResult{ResourceType: "Microsoft.Unknown/thing", ResourceID: "/res"}

	out := pipeline.New[templates.ARGQueryResult]()
	go func() {
		defer out.Close()
		require.NoError(t, e.Enrich(result, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)
}

func TestEnrich_MutatesProperties(t *testing.T) {
	defer plugin.ResetAzureEnricherRegistry()

	plugin.RegisterAzureEnricher("microsoft.web/sites", func(_ plugin.AzureEnricherConfig, r *templates.ARGQueryResult) error {
		r.Properties["authEnabled"] = false
		return nil
	})

	e := NewAzureEnricher(context.Background(), nil, 120*time.Second)
	result := templates.ARGQueryResult{ResourceType: "Microsoft.Web/sites", ResourceID: "/res"}

	out := pipeline.New[templates.ARGQueryResult]()
	go func() {
		defer out.Close()
		require.NoError(t, e.Enrich(result, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, false, items[0].Properties["authEnabled"])
}

func TestEnrich_ErrorStillForwards(t *testing.T) {
	defer plugin.ResetAzureEnricherRegistry()

	plugin.RegisterAzureEnricher("microsoft.web/sites", func(_ plugin.AzureEnricherConfig, _ *templates.ARGQueryResult) error {
		return fmt.Errorf("sdk call failed")
	})

	e := NewAzureEnricher(context.Background(), nil, 120*time.Second)
	result := templates.ARGQueryResult{ResourceType: "Microsoft.Web/sites", ResourceID: "/res"}

	out := pipeline.New[templates.ARGQueryResult]()
	go func() {
		defer out.Close()
		require.NoError(t, e.Enrich(result, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1, "result should be forwarded even on enricher error")
}

func TestEnrich_MultipleEnrichersAllRun(t *testing.T) {
	defer plugin.ResetAzureEnricherRegistry()

	plugin.RegisterAzureEnricher("microsoft.web/sites", func(_ plugin.AzureEnricherConfig, r *templates.ARGQueryResult) error {
		r.Properties["a"] = true
		return nil
	})
	plugin.RegisterAzureEnricher("microsoft.web/sites", func(_ plugin.AzureEnricherConfig, r *templates.ARGQueryResult) error {
		r.Properties["b"] = true
		return nil
	})

	e := NewAzureEnricher(context.Background(), nil, 120*time.Second)
	result := templates.ARGQueryResult{ResourceType: "Microsoft.Web/sites", ResourceID: "/res"}

	out := pipeline.New[templates.ARGQueryResult]()
	go func() {
		defer out.Close()
		require.NoError(t, e.Enrich(result, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, true, items[0].Properties["a"])
	assert.Equal(t, true, items[0].Properties["b"])
}

func TestEnrich_CaseInsensitiveResourceType(t *testing.T) {
	defer plugin.ResetAzureEnricherRegistry()

	plugin.RegisterAzureEnricher("microsoft.web/sites", func(_ plugin.AzureEnricherConfig, r *templates.ARGQueryResult) error {
		r.Properties["found"] = true
		return nil
	})

	e := NewAzureEnricher(context.Background(), nil, 120*time.Second)
	result := templates.ARGQueryResult{ResourceType: "Microsoft.Web/Sites", ResourceID: "/res"}

	out := pipeline.New[templates.ARGQueryResult]()
	go func() {
		defer out.Close()
		require.NoError(t, e.Enrich(result, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, true, items[0].Properties["found"])
}

func TestEnrich_NilProperties_Initialized(t *testing.T) {
	defer plugin.ResetAzureEnricherRegistry()

	plugin.RegisterAzureEnricher("microsoft.web/sites", func(_ plugin.AzureEnricherConfig, r *templates.ARGQueryResult) error {
		r.Properties["key"] = "value"
		return nil
	})

	e := NewAzureEnricher(context.Background(), nil, 120*time.Second)
	result := templates.ARGQueryResult{ResourceType: "Microsoft.Web/sites", ResourceID: "/res"}

	out := pipeline.New[templates.ARGQueryResult]()
	go func() {
		defer out.Close()
		require.NoError(t, e.Enrich(result, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	assert.Equal(t, "value", items[0].Properties["key"])
}
