package recon

import (
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
