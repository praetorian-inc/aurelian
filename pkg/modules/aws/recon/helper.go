package recon

import (
	"fmt"
	"slices"
	"strings"

	helpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/aws/resourcetypes"
)

// resolveRegions resolves the "all" keyword to actual enabled regions
func resolveRegions(
	regions []string, profile string, profileDir string,
) ([]string, error) {
	if len(regions) == 1 && strings.ToLower(regions[0]) == "all" {
		return helpers.EnabledRegions(profile, profileDir)
	}
	return regions, nil
}

func selectResourceTypes(scanType string) []string {
	if strings.ToLower(scanType) == "summary" {
		return resourcetypes.GetSummary()
	}
	return resourcetypes.GetAll()
}

func resolveRequestedResourceTypes(requested []string, supported []string) ([]string, error) {
	if len(requested) == 0 || (len(requested) == 1 && strings.EqualFold(requested[0], "all")) {
		return supported, nil
	}

	for _, resourceType := range requested {
		if !slices.Contains(supported, resourceType) {
			return nil, fmt.Errorf("unsupported resource type %q; supported: %v", resourceType, supported)
		}
	}

	return requested, nil
}
