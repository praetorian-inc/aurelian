package recon

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/praetorian-inc/aurelian/pkg/azure/extraction"
	"github.com/praetorian-inc/aurelian/pkg/azure/resourcegraph"
	azuretypes "github.com/praetorian-inc/aurelian/pkg/azure/types"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// validSubscriptionID matches a standard Azure subscription UUID.
var validSubscriptionID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// resolveSubscriptionIDs returns the given IDs directly, or if ids is ["all"],
// lists all accessible subscriptions and returns their IDs.
func resolveSubscriptionIDs(ids []string, resolver subscriptionResolver) ([]string, error) {
	if len(ids) == 1 && strings.EqualFold(ids[0], "all") {
		subs, err := resolver.ListAllSubscriptions()
		if err != nil {
			return nil, fmt.Errorf("failed to list subscriptions: %w", err)
		}
		resolved := make([]string, 0, len(subs))
		for _, sub := range subs {
			resolved = append(resolved, sub.ID)
		}
		return resolved, nil
	}
	return ids, nil
}

func subscriptionToListerInput(sub azuretypes.SubscriptionInfo, out *pipeline.P[resourcegraph.ListerInput]) error {
	out.Send(resourcegraph.ListerInput{Subscription: sub})
	return nil
}

func toAurelianModel(r output.AzureResource, out *pipeline.P[model.AurelianModel]) error {
	out.Send(r)
	return nil
}

// hydrateFromARG enriches a slice of AzureResource in-place with metadata
// (Location, DisplayName, TenantID) from Azure Resource Graph. Resources not
// indexed by ARG (e.g., policy definitions, deployments) are left unchanged.
func hydrateFromARG(cred azcore.TokenCredential, resources []output.AzureResource) {
	if len(resources) == 0 || cred == nil {
		return
	}

	// Group resource IDs by subscription for batched ARG queries.
	bySub := make(map[string][]int) // subscriptionID → indices into resources
	for i, r := range resources {
		bySub[r.SubscriptionID] = append(bySub[r.SubscriptionID], i)
	}

	client, err := armresourcegraph.NewClient(cred, nil)
	if err != nil {
		slog.Warn("could not create ARG client for resource hydration", "error", err)
		return
	}

	for subID, indices := range bySub {
		// Build a query that fetches all resources by ID in one call.
		// Escape single quotes in resource IDs to prevent KQL injection.
		ids := make([]string, len(indices))
		for j, idx := range indices {
			escaped := strings.ReplaceAll(strings.ToLower(resources[idx].ResourceID), "'", "''")
			ids[j] = fmt.Sprintf("'%s'", escaped)
		}
		query := fmt.Sprintf(
			"Resources | where tolower(id) in (%s) | project id, name, type, location, tenantId",
			strings.Join(ids, ", "),
		)

		resp, err := client.Resources(context.Background(), armresourcegraph.QueryRequest{
			Query:         &query,
			Subscriptions: []*string{&subID},
		}, nil)
		if err != nil {
			slog.Warn("ARG hydration query failed, continuing with parsed-only fields",
				"subscription", subID, "error", err)
			continue
		}

		// Index results by lowercase ID for matching.
		type argResult struct {
			Location string
			Name     string
			TenantID string
		}
		lookup := make(map[string]argResult)
		if data, ok := resp.Data.([]any); ok {
			for _, item := range data {
				m, ok := item.(map[string]any)
				if !ok {
					continue
				}
				rid, _ := m["id"].(string)
				lookup[strings.ToLower(rid)] = argResult{
					Location: strVal(m, "location"),
					Name:     strVal(m, "name"),
					TenantID: strVal(m, "tenantId"),
				}
			}
		}

		// Apply hydrated fields back to resources.
		for _, idx := range indices {
			if result, ok := lookup[strings.ToLower(resources[idx].ResourceID)]; ok {
				resources[idx].Location = result.Location
				resources[idx].TenantID = result.TenantID
				if resources[idx].DisplayName == "" {
					resources[idx].DisplayName = result.Name
				}
			}
		}
	}
}

func strVal(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

// azureResourceFromID parses a full Azure resource ID into an AzureResource.
// This is the Azure equivalent of AWS's ARN-based resource lookup in collectInputs.
func azureResourceFromID(id string) (output.AzureResource, error) {
	subID, rg, _, err := extraction.ParseAzureResourceID(id)
	if err != nil {
		return output.AzureResource{}, fmt.Errorf("invalid resource ID %q: %w", id, err)
	}

	if !validSubscriptionID.MatchString(subID) {
		return output.AzureResource{}, fmt.Errorf("invalid subscription ID %q in resource ID: expected UUID format", subID)
	}

	resourceType, err := extraction.ResourceTypeFromID(id)
	if err != nil {
		return output.AzureResource{}, fmt.Errorf("cannot determine resource type from %q: %w", id, err)
	}

	return output.AzureResource{
		SubscriptionID: subID,
		ResourceGroup:  rg,
		ResourceType:   resourceType,
		ResourceID:     id,
	}, nil
}
