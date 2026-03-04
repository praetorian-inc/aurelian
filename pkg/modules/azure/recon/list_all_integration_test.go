//go:build integration

package recon

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
)

// TestAzureListAllResourceEnumeration provisions 16 Azure resource types via
// Terraform, then runs the azure/recon/list-all module and asserts every
// provisioned resource ID appears in the results.
//
// Azure Resource Graph has eventual consistency -- newly created resources may
// take up to a few minutes to appear. The test includes a retry loop with
// increasing delays to handle this propagation window.
func TestAzureListAllResourceEnumeration(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/list-all")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAzure, plugin.CategoryRecon, "list-all")
	if !ok {
		t.Fatal("azure list-all module not registered")
	}

	subscriptionID := fixture.Output("subscription_id")
	allResourceIDs := fixture.OutputList("all_resource_ids")
	t.Logf("subscription: %s, expecting %d resource IDs", subscriptionID, len(allResourceIDs))

	cfg := plugin.Config{
		Args: map[string]any{
			"subscription-id": []string{subscriptionID},
		},
		Context: context.Background(),
	}

	// Retry loop to handle ARG propagation delay.
	// Delays: 0s, 10s, 20s, 30s, 40s, 50s (total max ~2.5 minutes).
	var results []model.AurelianModel
	var lastErr error
	const maxAttempts = 6

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			delay := time.Duration(attempt*10) * time.Second
			t.Logf("ARG propagation retry %d/%d, waiting %s...", attempt, maxAttempts-1, delay)
			time.Sleep(delay)
		}

		results, lastErr = testutil.RunAndCollect(t, mod, cfg)
		if lastErr != nil {
			t.Logf("attempt %d: module returned error: %v", attempt, lastErr)
			continue
		}

		t.Logf("attempt %d: got %d results", attempt, len(results))

		// Check if all expected resources are present.
		allFound := true
		for _, id := range allResourceIDs {
			if !testutil.ResultsContainString(results, id) {
				allFound = false
				break
			}
		}

		if allFound {
			t.Logf("attempt %d: all %d expected resources found", attempt, len(allResourceIDs))
			break
		}

		// Log which resources are still missing for debugging.
		var missing []string
		for _, id := range allResourceIDs {
			if !testutil.ResultsContainString(results, id) {
				missing = append(missing, id)
			}
		}
		t.Logf("attempt %d: %d/%d found, missing %d: %v", attempt, len(allResourceIDs)-len(missing), len(allResourceIDs), len(missing), missing)
	}

	require.NoError(t, lastErr)
	testutil.AssertMinResults(t, results, len(allResourceIDs))

	// Final assertion: every Terraform-created resource must appear in results.
	// testutil assertions use case-insensitive matching, which handles Azure
	// Resource Graph's casing normalization vs Terraform outputs.
	for _, id := range allResourceIDs {
		testutil.AssertResultContainsString(t, results, id)
	}
	t.Logf("all %d expected resources verified in results", len(allResourceIDs))
}
