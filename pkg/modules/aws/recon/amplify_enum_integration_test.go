//go:build integration

package recon

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAmplifyEnum(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/amplify")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "amplify-discover")
	if !ok {
		t.Fatal("amplify-discover module not registered in plugin system")
	}

	appID := fixture.Output("app_id")

	cfg := plugin.Config{
		Args: map[string]any{
			"distributions": []string{appID},
			"concurrency":   4,
		},
		Context: context.Background(),
	}

	results, err := testutil.RunAndCollect(t, mod, cfg)
	require.NoError(t, err)
	require.Len(t, results, 1, "expected one AnalyzeResult per distribution")

	ar, ok := results[0].(output.AnalyzeResult)
	require.True(t, ok, "result should be output.AnalyzeResult, got %T", results[0])
	assert.Equal(t, "amplify-discover", ar.Module)
	assert.Equal(t, appID, ar.Input)

	var payload amplifyEnumResult
	require.NoError(t, json.Unmarshal(ar.Results, &payload))

	assert.Equal(t, appID, payload.DistributionID)
	require.NotEmpty(t, payload.Branches, "deployed branches should be discovered")

	names := make([]string, len(payload.Branches))
	for i, b := range payload.Branches {
		names[i] = b.Name
	}

	t.Run("discovers main branch", func(t *testing.T) {
		assert.Contains(t, names, "main", "main branch should be discovered among %v", names)
	})

	t.Run("discovers dev branch", func(t *testing.T) {
		assert.Contains(t, names, "dev", "dev branch should be discovered among %v", names)
	})

	t.Run("reports app-id-scoped URLs", func(t *testing.T) {
		for _, b := range payload.Branches {
			assert.Contains(t, b.URL, appID, "URL must reference the test app's distribution ID")
			assert.Contains(t, b.URL, ".amplifyapp.com")
		}
	})

	t.Run("branches return expected status codes", func(t *testing.T) {
		// Deployed Amplify branches serve content via CloudFront.
		// Accept 200 (served), 301/302 (redirect to canonical host), and 403
		// (protected but reachable) — anything else indicates a broken fixture.
		allowed := []int{http.StatusOK, http.StatusMovedPermanently, http.StatusFound, http.StatusForbidden}
		for _, b := range payload.Branches {
			assert.Contains(t, allowed, b.StatusCode, "branch %s returned unexpected status %d", b.Name, b.StatusCode)
		}
	})

	t.Run("branches reference declared fixture names only", func(t *testing.T) {
		// Our fixture deploys only main + dev. Any other discovered branch
		// means the prober matched a default-branch name against a stale
		// deployment or there is a real bug in the distribution filter.
		declared := []string{"main", "dev"}
		for _, name := range names {
			assert.True(t, slices.Contains(declared, name), "unexpected branch %q discovered — fixture only deploys %v", name, declared)
		}
	})

	t.Run("results sorted by branch name", func(t *testing.T) {
		sortedNames := slices.Clone(names)
		slices.Sort(sortedNames)
		assert.Equal(t, sortedNames, names, "probeDistribution should return branches sorted alphabetically")
	})
}
