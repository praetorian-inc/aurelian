package recon

import (
	"fmt"
	"slices"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/aws/resourcetypes"
)

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
