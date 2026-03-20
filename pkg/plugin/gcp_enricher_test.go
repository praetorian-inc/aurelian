package plugin_test

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGCPEnricherRegistry(t *testing.T) {
	plugin.ResetGCPEnricherRegistry()
	enrichers := plugin.GetGCPEnrichers("compute.googleapis.com/Instance")
	assert.Empty(t, enrichers)

	called := false
	plugin.RegisterGCPEnricher("compute.googleapis.com/Instance", func(cfg plugin.GCPEnricherConfig, r *output.GCPResource) error {
		called = true
		return nil
	})

	enrichers = plugin.GetGCPEnrichers("compute.googleapis.com/Instance")
	require.Len(t, enrichers, 1)

	r := &output.GCPResource{ResourceType: "compute.googleapis.com/Instance"}
	err := enrichers[0](plugin.GCPEnricherConfig{Context: context.Background()}, r)
	assert.NoError(t, err)
	assert.True(t, called)
	assert.Empty(t, plugin.GetGCPEnrichers("storage.googleapis.com/Bucket"))
	plugin.ResetGCPEnricherRegistry()
}
