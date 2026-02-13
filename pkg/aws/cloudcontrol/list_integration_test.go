//go:build integration

package cloudcontrol

import (
	_ "embed"
	"encoding/json"
	"fmt"

	helpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/aws/resourcetypes"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/testutils"
	"github.com/stretchr/testify/require"
	"testing"
)

//go:embed cloud-control-output.json
var expectedCloudControlOutput string

type expectedCloudControlResult struct {
	Data map[string][]output.CloudResource `json:"Data"`
}

func Test_CloudControl_ListAllInAllRegions(t *testing.T) {
	cfg := testutils.SetupIntegrationConfig(t)

	regions, err := helpers.EnabledRegions(cfg.Profile, cfg.ProfileDir)
	require.NoError(t, err)

	lister := NewCloudControlLister(5, cfg.Profile, cfg.ProfileDir)
	results, err := lister.List(regions, resourcetypes.GetAll())
	require.NoError(t, err)
	require.NotNil(t, results)

	var expectedResults []expectedCloudControlResult
	require.NoError(t, json.Unmarshal([]byte(expectedCloudControlOutput), &expectedResults))
	require.Len(t, expectedResults, 1, "cloud-control-output.json must contain exactly one result")
	require.NotNil(t, expectedResults[0].Data)

	for key, expectedResources := range expectedResults[0].Data {
		if len(expectedResources) == 0 {
			continue
		}

		actualResources, ok := results[key]
		require.Truef(t, ok, "expected key %q to exist in live results", key)
		requireResourcesContained(t, key, expectedResources, actualResources)
	}
}

// Useful method to debug specific resource failures from the above test
func VerifyResourceFound(t *testing.T, resourceARN string, results map[string][]output.CloudResource) {
	t.Helper()

	for _, resources := range results {
		for _, resource := range resources {
			if resource.ARN == resourceARN {
				return
			}
		}
	}

	require.Failf(t, "resource not found", "expected ARN %q was not found in live results", resourceARN)
}

func requireResourcesContained(t *testing.T, key string, expected []output.CloudResource, actual []output.CloudResource) {
	t.Helper()

	actualFingerprints := make(map[string]bool, len(actual))
	for _, resource := range actual {
		actualFingerprints[resourceFingerprint(t, resource)] = true
	}

	for _, expectedResource := range expected {
		fp := resourceFingerprint(t, expectedResource)
		found := actualFingerprints[fp]
		require.True(t, found, "missing expected resource for key %q: %s", key, fp)
	}
}

func resourceFingerprint(t *testing.T, resource output.CloudResource) string {
	t.Helper()

	raw, err := json.Marshal(resource)
	require.NoError(t, err)

	return fmt.Sprintf("%s|%s", resource.ResourceID, string(raw))
}
