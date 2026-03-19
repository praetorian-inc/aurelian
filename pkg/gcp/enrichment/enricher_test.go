package enrichment

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGCPEnricher_PassThrough(t *testing.T) {
	plugin.ResetGCPEnricherRegistry()

	enricher := NewGCPEnricher(plugin.GCPCommonRecon{})
	out := pipeline.New[output.GCPResource]()
	go func() {
		defer out.Close()
		err := enricher.Enrich(output.NewGCPResource("proj", "storage.googleapis.com/Bucket", "id"), out)
		assert.NoError(t, err)
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "proj", items[0].ProjectID)
}

func TestGCPEnricher_RunsRegisteredEnricher(t *testing.T) {
	plugin.ResetGCPEnricherRegistry()

	plugin.RegisterGCPEnricher("storage.googleapis.com/Bucket", func(cfg plugin.GCPEnricherConfig, r *output.GCPResource) error {
		if r.Properties == nil {
			r.Properties = make(map[string]any)
		}
		r.Properties["enriched"] = true
		return nil
	})

	enricher := NewGCPEnricher(plugin.GCPCommonRecon{})
	out := pipeline.New[output.GCPResource]()
	go func() {
		defer out.Close()
		err := enricher.Enrich(output.NewGCPResource("proj", "storage.googleapis.com/Bucket", "id"), out)
		assert.NoError(t, err)
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, true, items[0].Properties["enriched"])

	plugin.ResetGCPEnricherRegistry()
}
