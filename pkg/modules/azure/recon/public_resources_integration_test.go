//go:build integration

package recon

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAzurePublicResources(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/public-resources")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAzure, plugin.CategoryRecon, "public-resources")
	if !ok {
		t.Fatal("azure public-resources module not registered in plugin system")
	}

	subscriptionID := fixture.Output("subscription_id")

	results, err := testutil.RunAndCollect(t, mod, plugin.Config{
		Args: map[string]any{
			"subscription-id": []string{subscriptionID},
		},
		Context: context.Background(),
	})
	require.NoError(t, err)
	testutil.AssertMinResults(t, results, 1)

	// Collect risks from results.
	var risks []output.AurelianRisk
	for _, r := range results {
		if risk, ok := r.(output.AurelianRisk); ok {
			risks = append(risks, risk)
		}
	}
	require.NotEmpty(t, risks, "should emit at least one risk")

	// Validate risk fields on all results.
	for _, risk := range risks {
		assert.NotEmpty(t, risk.Name, "risk Name must not be empty")
		assert.NotEmpty(t, risk.Severity, "risk Severity must not be empty")
		assert.NotEmpty(t, risk.ImpactedARN, "risk ImpactedARN must not be empty")
		assert.NotEmpty(t, risk.Context, "risk Context must not be empty")
	}

	t.Run("detects public storage account", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("storage_account_id"))
	})

	t.Run("detects public key vault", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("key_vault_id"))
	})

	t.Run("detects public sql server", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("sql_server_id"))
	})

	t.Run("detects public container registry", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("acr_id"))
	})
}

