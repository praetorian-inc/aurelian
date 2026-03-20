package recon

import (
	"fmt"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
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

func collectInputs(opts plugin.AWSCommonRecon, resolvedTypes []string) ([]string, error) {
	if len(opts.ResourceARN) > 0 {
		return opts.ResourceARN, nil
	}

	resourceTypes, err := resolveRequestedResourceTypes(opts.ResourceType, resolvedTypes)
	if err != nil {
		return nil, err
	}

	return resourceTypes, nil
}
