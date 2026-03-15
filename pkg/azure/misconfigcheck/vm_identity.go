package misconfigcheck

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"

	"github.com/praetorian-inc/aurelian/pkg/templates"
)

// privilegedRoleIDs are the well-known role definition ID suffixes for
// Owner, Contributor, and User Access Administrator.
var privilegedRoleIDs = map[string]bool{
	"8e3af657-a8ff-443c-a75c-2fe8c4bcb635": true, // Owner
	"b24988ac-6180-42a0-ab88-20f7382dd24c": true, // Contributor
	"18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": true, // User Access Administrator
}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func (e *Enricher) checkVMPrivilegedIdentity(result templates.ARGQueryResult) (bool, error) {
	subID, _, _, err := ParseResource(result)
	if err != nil {
		return false, err
	}

	principalID := ""
	if props := result.Properties; props != nil {
		if pid, ok := props["principalId"].(string); ok {
			principalID = pid
		}
	}
	if principalID == "" {
		return false, nil
	}

	// Validate principalID is a UUID to prevent OData filter injection.
	if !uuidPattern.MatchString(principalID) {
		return false, nil
	}

	client, err := armauthorization.NewRoleAssignmentsClient(subID, e.cred, nil)
	if err != nil {
		return false, fmt.Errorf("creating role assignments client: %w", err)
	}

	filter := fmt.Sprintf("assignedTo('%s')", principalID)
	pager := client.NewListForSubscriptionPager(&armauthorization.RoleAssignmentsClientListForSubscriptionOptions{
		Filter: &filter,
	})

	for pager.More() {
		page, err := pager.NextPage(e.ctx)
		if err != nil {
			return false, fmt.Errorf("listing role assignments for %s: %w", principalID, err)
		}
		for _, ra := range page.Value {
			if ra.Properties == nil || ra.Properties.RoleDefinitionID == nil {
				continue
			}
			roleDefID := strings.ToLower(*ra.Properties.RoleDefinitionID)
			guid := roleDefID[strings.LastIndex(roleDefID, "/")+1:]
			if privilegedRoleIDs[guid] {
				return true, nil
			}
		}
	}

	return false, nil
}
