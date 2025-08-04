package azure

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/managementgroups/armmanagementgroups"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AzureRoleAssignmentsCollectorLink struct {
	*chain.Base
}

func NewAzureRoleAssignmentsCollectorLink(configs ...cfg.Config) chain.Link {
	l := &AzureRoleAssignmentsCollectorLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureRoleAssignmentsCollectorLink) Process(input any) error {
	subscription, ok := input.(string)
	if !ok {
		return fmt.Errorf("expected string input, got %T", input)
	}

	workerCount, _ := cfg.As[int](l.Arg("workers"))
	if workerCount == 0 {
		workerCount = 5 // default
	}

	// Get Azure credentials
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("failed to get Azure credentials: %w", err)
	}

	// Get subscription details first to ensure we have access
	subDetails, err := l.getSubscriptionDetails(cred, subscription)
	if err != nil {
		return fmt.Errorf("failed to get subscription details: %w", err)
	}

	assignments := make([]*types.RoleAssignmentDetails, 0)
	var mu sync.Mutex

	// Try to get management group assignments
	mgmtClient, err := armmanagementgroups.NewClient(cred, &arm.ClientOptions{})
	if err == nil {
		mgmtAssignments, err := l.getMgmtGroupRoleAssignments(mgmtClient, subscription)
		if err != nil {
			slog.Debug("Failed to get management group assignments", slog.String("error", err.Error()))
		} else {
			mu.Lock()
			assignments = append(assignments, mgmtAssignments...)
			mu.Unlock()
		}
	}

	// Get subscription level assignments
	authClient, err := armauthorization.NewRoleAssignmentsClient(subscription, cred, &arm.ClientOptions{})
	if err != nil {
		return fmt.Errorf("failed to create authorization client: %w", err)
	}

	subAssignments, err := l.getSubscriptionRoleAssignments(authClient, subscription, *subDetails.DisplayName)
	if err != nil {
		slog.Debug("Failed to get subscription assignments", slog.String("error", err.Error()))
	} else {
		mu.Lock()
		assignments = append(assignments, subAssignments...)
		mu.Unlock()
	}

	// Get resource group level assignments
	resourceClient, err := armresources.NewClient(subscription, cred, &arm.ClientOptions{})
	if err != nil {
		return fmt.Errorf("failed to create resources client: %w", err)
	}

	rgAssignments, err := l.getResourceGroupRoleAssignments(resourceClient, authClient, subscription, *subDetails.DisplayName)
	if err != nil {
		slog.Debug("Failed to get resource group assignments", slog.String("error", err.Error()))
	} else {
		mu.Lock()
		assignments = append(assignments, rgAssignments...)
		mu.Unlock()
	}

	if len(assignments) > 0 {
		return l.Send(assignments)
	}

	return nil
}

func (l *AzureRoleAssignmentsCollectorLink) Params() []cfg.Param {
	return options.AzureReconBaseOptions()
}

// getSubscriptionDetails gets details about an Azure subscription
func (l *AzureRoleAssignmentsCollectorLink) getSubscriptionDetails(cred *azidentity.DefaultAzureCredential, subscriptionID string) (*armsubscriptions.Subscription, error) {
	client, err := armsubscriptions.NewClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create subscription client: %v", err)
	}
	
	sub, err := client.Get(l.Context(), subscriptionID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get subscription: %v", err)
	}
	
	return &sub.Subscription, nil
}

// getMgmtGroupRoleAssignments gets role assignments at the management group level
func (l *AzureRoleAssignmentsCollectorLink) getMgmtGroupRoleAssignments(client *armmanagementgroups.Client, subscriptionID string) ([]*types.RoleAssignmentDetails, error) {
	assignments := make([]*types.RoleAssignmentDetails, 0)
	
	// This is a simplified implementation - in practice, you'd need to:
	// 1. Find which management group the subscription belongs to
	// 2. Get role assignments at that level
	// For now, we'll skip this complex lookup as it requires additional API calls
	
	return assignments, nil
}

// getSubscriptionRoleAssignments gets role assignments at the subscription level
func (l *AzureRoleAssignmentsCollectorLink) getSubscriptionRoleAssignments(client *armauthorization.RoleAssignmentsClient, subscriptionID, subscriptionName string) ([]*types.RoleAssignmentDetails, error) {
	assignments := make([]*types.RoleAssignmentDetails, 0)
	
	// Get role definition client to look up role names
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure credential for role definitions: %v", err)
	}
	roleDefClient, err := armauthorization.NewRoleDefinitionsClient(cred, &arm.ClientOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create role definitions client: %v", err)
	}

	// List role assignments for the subscription
	subscriptionScope := fmt.Sprintf("/subscriptions/%s", subscriptionID)
	pager := client.NewListForScopePager(subscriptionScope, &armauthorization.RoleAssignmentsClientListForScopeOptions{})
	
	for pager.More() {
		page, err := pager.NextPage(l.Context())
		if err != nil {
			return nil, fmt.Errorf("failed to get role assignments page: %v", err)
		}
		
		for _, assignment := range page.Value {
			if assignment == nil || assignment.Properties == nil {
				continue
			}
			
			roleAssignment := &types.RoleAssignmentDetails{
				SubscriptionID:     subscriptionID,
				SubscriptionName:   subscriptionName,
				PrincipalID:        *assignment.Properties.PrincipalID,
				PrincipalType:      "Unknown", // Would need additional API call to determine
				RoleDefinitionID:   *assignment.Properties.RoleDefinitionID,
				Scope:              *assignment.Properties.Scope,
				ScopeType:          "Subscription",
				ScopeDisplayName:   subscriptionName,
			}
			
			// Try to get role display name
			if roleDefResp, err := roleDefClient.Get(l.Context(), *assignment.Properties.Scope, *assignment.Properties.RoleDefinitionID, nil); err == nil {
				if roleDefResp.RoleDefinition.Properties != nil && roleDefResp.RoleDefinition.Properties.RoleName != nil {
					roleAssignment.RoleDisplayName = *roleDefResp.RoleDefinition.Properties.RoleName
				}
			}
			
			assignments = append(assignments, roleAssignment)
		}
	}
	
	return assignments, nil
}

// getResourceGroupRoleAssignments gets role assignments at the resource group level
func (l *AzureRoleAssignmentsCollectorLink) getResourceGroupRoleAssignments(resourceClient *armresources.Client, authClient *armauthorization.RoleAssignmentsClient, subscriptionID, subscriptionName string) ([]*types.RoleAssignmentDetails, error) {
	assignments := make([]*types.RoleAssignmentDetails, 0)
	
	// Get role definition client to look up role names
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure credential for role definitions: %v", err)
	}
	roleDefClient, err := armauthorization.NewRoleDefinitionsClient(cred, &arm.ClientOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create role definitions client: %v", err)
	}

	// Create resource groups client
	rgClient, err := armresources.NewResourceGroupsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource groups client: %v", err)
	}
	
	// List all resource groups in the subscription
	rgPager := rgClient.NewListPager(nil)
	
	for rgPager.More() {
		rgPage, err := rgPager.NextPage(l.Context())
		if err != nil {
			return nil, fmt.Errorf("failed to get resource groups page: %v", err)
		}
		
		for _, rg := range rgPage.Value {
			if rg == nil || rg.Name == nil {
				continue
			}
			
			// Get role assignments for this resource group
			rgScope := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", subscriptionID, *rg.Name)
			assignmentPager := authClient.NewListForScopePager(rgScope, &armauthorization.RoleAssignmentsClientListForScopeOptions{})
			
			for assignmentPager.More() {
				assignmentPage, err := assignmentPager.NextPage(l.Context())
				if err != nil {
					slog.Debug("Failed to get role assignments for resource group", slog.String("rg", *rg.Name), slog.String("error", err.Error()))
					continue
				}
				
				for _, assignment := range assignmentPage.Value {
					if assignment == nil || assignment.Properties == nil {
						continue
					}
					
					roleAssignment := &types.RoleAssignmentDetails{
						SubscriptionID:     subscriptionID,
						SubscriptionName:   subscriptionName,
						PrincipalID:        *assignment.Properties.PrincipalID,
						PrincipalType:      "Unknown", // Would need additional API call to determine
						RoleDefinitionID:   *assignment.Properties.RoleDefinitionID,
						Scope:              *assignment.Properties.Scope,
						ScopeType:          "ResourceGroup",
						ScopeDisplayName:   *rg.Name,
					}
					
					// Try to get role display name
					if roleDefResp, err := roleDefClient.Get(l.Context(), *assignment.Properties.Scope, *assignment.Properties.RoleDefinitionID, nil); err == nil {
						if roleDefResp.RoleDefinition.Properties != nil && roleDefResp.RoleDefinition.Properties.RoleName != nil {
							roleAssignment.RoleDisplayName = *roleDefResp.RoleDefinition.Properties.RoleName
						}
					}
					
					assignments = append(assignments, roleAssignment)
				}
			}
		}
	}
	
	return assignments, nil
}