//go:build integration

package recon

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"

	// Register Azure modules so plugin.Get can find them.
	_ "github.com/praetorian-inc/aurelian/pkg/modules/azure/recon"
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

		p1 := pipeline.From(cfg)
		p2 := pipeline.New[model.AurelianModel]()
		pipeline.Pipe(p1, mod.Run, p2)

		results, lastErr = p2.Collect()
		if lastErr != nil {
			t.Logf("attempt %d: module returned error: %v", attempt, lastErr)
			continue
		}

		t.Logf("attempt %d: got %d results", attempt, len(results))

		// Check if all expected resources are present.
		allFound := true
		for _, id := range allResourceIDs {
			if !resultsContainString(results, id) {
				allFound = false
				break
			}
		}

		if allFound {
			break
		}
	}

	require.NoError(t, lastErr)
	testutil.AssertMinResults(t, results, len(allResourceIDs))

	// Final assertion: every Terraform-created resource must appear in results.
	for _, id := range allResourceIDs {
		testutil.AssertResultContainsString(t, results, id)
	}
}

// resultsContainString checks whether any result in the slice contains the
// given substring when serialized to JSON. This is used in the retry loop
// to determine if ARG has propagated all resources. It mirrors the logic of
// testutil.AssertResultContainsString but returns a bool instead of failing.
func resultsContainString(results []model.AurelianModel, substr string) bool {
	for _, r := range results {
		raw, err := json.Marshal(r)
		if err != nil {
			continue
		}
		if strings.Contains(string(raw), substr) {
			return true
		}
	}
	return false
}
