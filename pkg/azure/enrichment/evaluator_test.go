package enrichment

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvaluate_NoEvaluator_PassesThrough(t *testing.T) {
	defer plugin.ResetAzureEvaluatorRegistry()

	result := templates.ARGQueryResult{TemplateID: "arg_filtered_tmpl", ResourceID: "/res"}

	out := pipeline.New[templates.ARGQueryResult]()
	go func() {
		defer out.Close()
		require.NoError(t, Evaluate(result, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)
}

func TestEvaluate_Confirmed(t *testing.T) {
	defer plugin.ResetAzureEvaluatorRegistry()

	plugin.RegisterAzureEvaluator("test_tmpl", func(r templates.ARGQueryResult) bool {
		v, ok := r.Properties["flag"].(bool)
		return ok && v
	})

	result := templates.ARGQueryResult{
		TemplateID: "test_tmpl",
		ResourceID: "/res",
		Properties: map[string]any{"flag": true},
	}

	out := pipeline.New[templates.ARGQueryResult]()
	go func() {
		defer out.Close()
		require.NoError(t, Evaluate(result, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)
}

func TestEvaluate_Dropped(t *testing.T) {
	defer plugin.ResetAzureEvaluatorRegistry()

	plugin.RegisterAzureEvaluator("test_tmpl", func(r templates.ARGQueryResult) bool {
		v, ok := r.Properties["flag"].(bool)
		return ok && v
	})

	result := templates.ARGQueryResult{
		TemplateID: "test_tmpl",
		ResourceID: "/res",
		Properties: map[string]any{"flag": false},
	}

	out := pipeline.New[templates.ARGQueryResult]()
	go func() {
		defer out.Close()
		require.NoError(t, Evaluate(result, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	assert.Empty(t, items)
}

func TestEvaluate_MissingProperty_Drops(t *testing.T) {
	defer plugin.ResetAzureEvaluatorRegistry()

	plugin.RegisterAzureEvaluator("test_tmpl", func(r templates.ARGQueryResult) bool {
		v, ok := r.Properties["flag"].(bool)
		return ok && v
	})

	result := templates.ARGQueryResult{
		TemplateID: "test_tmpl",
		ResourceID: "/res",
		Properties: map[string]any{},
	}

	out := pipeline.New[templates.ARGQueryResult]()
	go func() {
		defer out.Close()
		require.NoError(t, Evaluate(result, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	assert.Empty(t, items)
}
