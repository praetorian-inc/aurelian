//go:build integration

package recon

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/require"
)

// TestAzurePublicResourcesModule provisions publicly-accessible Azure resources
// via Terraform, runs the azure/recon/public-resources module, and asserts each
// expected template detects the corresponding resource.
func TestAzurePublicResourcesModule(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/public-resources")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAzure, plugin.CategoryRecon, "public-resources")
	if !ok {
		t.Fatal("azure public-resources module not registered")
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

	t.Run("detects public storage account", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("storage_account_id"))
	})

	t.Run("detects public sql server", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("sql_server_id"))
	})
}
