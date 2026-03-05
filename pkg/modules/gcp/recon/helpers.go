package recon

import (
	"slices"
	"strings"
)

func filterResourceTypes(requested []string, supported []string) []string {
	if len(requested) == 1 && strings.EqualFold(requested[0], "all") {
		return supported
	}
	var filtered []string
	for _, r := range requested {
		canonical, err := resolveAlias(r)
		if err != nil {
			continue
		}
		if slices.Contains(supported, canonical) {
			filtered = append(filtered, canonical)
		}
	}
	return filtered
}
