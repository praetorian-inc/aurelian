package enrichment

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
	"github.com/praetorian-inc/aurelian/test/azuretest"
)

func TestEnricherForwardsCredentialAndEnvironment(t *testing.T) {
	defer plugin.ResetAzureEnricherRegistry()
	cred := &azuretest.Credential{}
	env := azurecloud.Resolve("")
	env.Name = "caller-environment"
	called := false
	plugin.RegisterAzureEnricher("test/environment", func(cfg plugin.AzureEnricherConfig, _ *templates.ARGQueryResult) error {
		assert.Same(t, cred, cfg.Credential)
		assert.Equal(t, env, cfg.Env)
		called = true
		return nil
	})

	enricher := NewAzureEnricher(context.Background(), cred, env, time.Second)
	input := pipeline.From(templates.ARGQueryResult{ResourceType: "test/environment"})
	out := pipeline.New[templates.ARGQueryResult]()
	pipeline.Pipe(input, enricher.Enrich, out)
	items, err := out.Collect()
	require.NoError(t, err)
	assert.Len(t, items, 1)
	assert.True(t, called)
}
