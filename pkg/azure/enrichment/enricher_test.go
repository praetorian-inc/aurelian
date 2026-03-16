package enrichment

import (
	"context"
	"fmt"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnrich_UnregisteredTemplate_PassesThrough(t *testing.T) {
	defer plugin.ResetAzureEnricherRegistry()

	e := NewAzureConfigEnricher(context.Background(), nil)
	result := templates.ARGQueryResult{TemplateID: "no_enricher_needed", ResourceID: "/sub/rg/res"}

	out := pipeline.New[templates.ARGQueryResult]()
	go func() {
		defer out.Close()
		require.NoError(t, e.Enrich(result, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "no_enricher_needed", items[0].TemplateID)
}

func TestEnrich_ConfirmedResult_PassesThrough(t *testing.T) {
	defer plugin.ResetAzureEnricherRegistry()

	plugin.RegisterAzureEnricher("confirmed_tmpl", func(_ plugin.AzureEnricherConfig, _ templates.ARGQueryResult) (bool, error) {
		return true, nil
	})

	e := NewAzureConfigEnricher(context.Background(), nil)
	result := templates.ARGQueryResult{TemplateID: "confirmed_tmpl", ResourceID: "/sub/rg/res"}

	out := pipeline.New[templates.ARGQueryResult]()
	go func() {
		defer out.Close()
		require.NoError(t, e.Enrich(result, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)
}

func TestEnrich_DroppedResult_NotSent(t *testing.T) {
	defer plugin.ResetAzureEnricherRegistry()

	plugin.RegisterAzureEnricher("drop_tmpl", func(_ plugin.AzureEnricherConfig, _ templates.ARGQueryResult) (bool, error) {
		return false, nil
	})

	e := NewAzureConfigEnricher(context.Background(), nil)
	result := templates.ARGQueryResult{TemplateID: "drop_tmpl", ResourceID: "/sub/rg/res"}

	out := pipeline.New[templates.ARGQueryResult]()
	go func() {
		defer out.Close()
		require.NoError(t, e.Enrich(result, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	assert.Empty(t, items)
}

func TestEnrich_ErrorResult_DroppedAndLogged(t *testing.T) {
	defer plugin.ResetAzureEnricherRegistry()

	plugin.RegisterAzureEnricher("error_tmpl", func(_ plugin.AzureEnricherConfig, _ templates.ARGQueryResult) (bool, error) {
		return false, fmt.Errorf("sdk call failed")
	})

	e := NewAzureConfigEnricher(context.Background(), nil)
	result := templates.ARGQueryResult{TemplateID: "error_tmpl", ResourceID: "/sub/rg/res"}

	out := pipeline.New[templates.ARGQueryResult]()
	go func() {
		defer out.Close()
		require.NoError(t, e.Enrich(result, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	assert.Empty(t, items)
}

func TestEnrich_MultipleEnrichers_AllMustConfirm(t *testing.T) {
	defer plugin.ResetAzureEnricherRegistry()

	plugin.RegisterAzureEnricher("multi_tmpl", func(_ plugin.AzureEnricherConfig, _ templates.ARGQueryResult) (bool, error) {
		return true, nil
	})
	plugin.RegisterAzureEnricher("multi_tmpl", func(_ plugin.AzureEnricherConfig, _ templates.ARGQueryResult) (bool, error) {
		return false, nil // second enricher drops
	})

	e := NewAzureConfigEnricher(context.Background(), nil)
	result := templates.ARGQueryResult{TemplateID: "multi_tmpl", ResourceID: "/sub/rg/res"}

	out := pipeline.New[templates.ARGQueryResult]()
	go func() {
		defer out.Close()
		require.NoError(t, e.Enrich(result, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	assert.Empty(t, items, "should be dropped because second enricher returned false")
}
