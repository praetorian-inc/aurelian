//go:build integration

package cloudcontrol

import (
	helpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/aws/resourcetypes"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

var (
	EXPECTED_REGIONS = []string{
		"ap-northeast-1",
		"ap-northeast-2",
		"ap-northeast-3",
		"ap-south-1",
		"ap-southeast-1",
		"ap-southeast-2",
		"ca-central-1",
		"eu-central-1",
		"eu-north-1",
		"eu-west-1",
		"eu-west-2",
		"eu-west-3",
		"sa-east-1",
		"us-east-1",
		"us-east-2",
		"us-west-1",
		"us-west-2",
	}
)

//func Test_CloudControl_ListAllInAllRegions(t *testing.T) {
//	regions, err := helpers.EnabledRegions("nebula", "")
//	require.NoError(t, err)
//
//	results, err := ListAll(context.Background(), ListAllOptions{
//		ResourceTypes: resourcetypes.GetAll(),
//		Regions:       regions,
//		Concurrency:   5,
//		Profile:       "nebula",
//	})
//	require.NoError(t, err)
//	require.NotNil(t, results)
//
//	verifyRegionsPresent(t, results, EXPECTED_REGIONS...)
//}

func Test_CloudControl_ListAllInAllRegions(t *testing.T) {
	regions, err := helpers.EnabledRegions("nebula", "")
	require.NoError(t, err)

	lister := NewCloudControlLister(5, "nebula", "")
	results, err := lister.List(regions, resourcetypes.GetAll())
	require.NoError(t, err)
	require.NotNil(t, results)

	verifyRegionsPresent(t, results, EXPECTED_REGIONS...)
}

func verifyRegionsPresent(t *testing.T, results map[string][]output.CloudResource, regions ...string) {
	t.Helper()

	for _, region := range regions {
		verifyRegionPresent(t, results, region)
	}
}

func verifyRegionPresent(t *testing.T, results map[string][]output.CloudResource, region string) {
	t.Helper()

	regionFound := false
	for key, result := range results {
		if !strings.HasPrefix(key, region) {
		    continue
		}

		regionFound = true
		if len(result) > 0 {
			return
		}
	}

	if regionFound {
		t.Fatalf("region %s found, but with zero results", region)
		return
	}

	t.Fatalf("region %q not found in output", region)
}
