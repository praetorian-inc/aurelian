package recon

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/aws/resourcetypes"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// resolveRegions resolves the "all" keyword to actual enabled regions
func resolveRegions(
	regions []string, profile string, opts []*types.Option,
) ([]string, error) {
	if len(regions) == 1 && strings.ToLower(regions[0]) == "all" {
		return helpers.EnabledRegions(profile, opts)
	}
	return regions, nil
}

func flattenResults(
	allResults map[string]map[string][]output.CloudResource,
) map[string][]output.CloudResource {
	flatResults := make(map[string][]output.CloudResource)
	for region, regionResults := range allResults {
		for rt, resources := range regionResults {
			key := fmt.Sprintf("%s/%s", region, rt)
			flatResults[key] = resources
		}
	}
	return flatResults
}

func selectResourceTypes(scanType string) []string {
	if strings.ToLower(scanType) == "summary" {
		return resourcetypes.GetSummary()
	}
	return resourcetypes.GetAll()
}
