package enrichers

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"

	"github.com/praetorian-inc/aurelian/pkg/azure/enrichment"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("microsoft.compute/virtualmachines", enrichVMIdentity)
}

var privilegedRoleIDs = map[string]bool{
	"8e3af657-a8ff-443c-a75c-2fe8c4bcb635": true, // Owner
	"b24988ac-6180-42a0-ab88-20f7382dd24c": true, // Contributor
	"18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": true, // User Access Administrator
}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func enrichVMIdentity(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) error {
	subID, _, _, err := enrichment.ParseResource(*result)
	if err != nil {
		return err
	}

	principalID := ""
	if props := result.Properties; props != nil {
		if pid, ok := props["principalId"].(string); ok {
			principalID = pid
		}
	}
	if principalID == "" || !uuidPattern.MatchString(principalID) {
		result.Properties["hasPrivilegedManagedIdentity"] = false
		return nil
	}

	client, err := armauthorization.NewRoleAssignmentsClient(subID, cfg.Credential, nil)
	if err != nil {
		return fmt.Errorf("creating role assignments client: %w", err)
	}

	filter := fmt.Sprintf("assignedTo('%s')", principalID)
	pager := client.NewListForSubscriptionPager(&armauthorization.RoleAssignmentsClientListForSubscriptionOptions{
		Filter: &filter,
	})

	for pager.More() {
		page, err := pager.NextPage(cfg.Context)
		if err != nil {
			return fmt.Errorf("listing role assignments for %s: %w", principalID, err)
		}
		for _, ra := range page.Value {
			if ra.Properties == nil || ra.Properties.RoleDefinitionID == nil {
				continue
			}
			roleDefID := strings.ToLower(*ra.Properties.RoleDefinitionID)
			guid := roleDefID[strings.LastIndex(roleDefID, "/")+1:]
			if privilegedRoleIDs[guid] {
				result.Properties["hasPrivilegedManagedIdentity"] = true
				return nil
			}
		}
	}

	result.Properties["hasPrivilegedManagedIdentity"] = false
	return nil
}
