package enrichment

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/templates"
)

// ParseResource extracts subscription ID, resource group, and resource name
// from an ARG query result.
func ParseResource(result templates.ARGQueryResult) (subID, rg, name string, err error) {
	subID = result.SubscriptionID
	name = result.ResourceName

	parts := strings.Split(result.ResourceID, "/")
	for i, p := range parts {
		if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
			rg = parts[i+1]
			break
		}
	}
	if subID == "" || rg == "" || name == "" {
		return "", "", "", fmt.Errorf("cannot parse resource ID %q: sub=%q rg=%q name=%q",
			result.ResourceID, subID, rg, name)
	}
	return subID, rg, name, nil
}
