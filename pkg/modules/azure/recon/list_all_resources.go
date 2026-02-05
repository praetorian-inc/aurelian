package recon

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&ListAllResources{})
}

// ListAllResources lists all Azure resources across subscriptions
type ListAllResources struct{}

// ID returns the unique identifier for this module
func (m *ListAllResources) ID() string {
	return "list-all"
}

// Name returns the human-readable name
func (m *ListAllResources) Name() string {
	return "List All Resources"
}

// Description returns a detailed description
func (m *ListAllResources) Description() string {
	return "List all Azure resources across subscriptions with complete details including identifier. This might take a while for large subscriptions."
}

// Platform returns the cloud platform this module targets
func (m *ListAllResources) Platform() plugin.Platform {
	return plugin.PlatformAzure
}

// Category returns the module category
func (m *ListAllResources) Category() plugin.Category {
	return plugin.CategoryRecon
}

// OpsecLevel returns the operational security level
func (m *ListAllResources) OpsecLevel() string {
	return "stealth"
}

// Authors returns the list of module authors
func (m *ListAllResources) Authors() []string {
	return []string{"Praetorian"}
}

// References returns documentation and reference links
func (m *ListAllResources) References() []string {
	return []string{
		"https://learn.microsoft.com/en-us/azure/azure-resource-graph/overview",
		"https://learn.microsoft.com/en-us/azure/governance/resource-graph/concepts/query-language",
	}
}

// Parameters returns the list of parameters this module accepts
func (m *ListAllResources) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "module-name",
			Description: "name of the module for dynamic file naming",
			Type:        "string",
			Required:    false,
			Default:     "list-all",
		},
	}
}

// Run executes the module logic
func (m *ListAllResources) Run(cfg plugin.Config) ([]plugin.Result, error) {
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	// Get module name from args or use default
	moduleName, _ := cfg.Args["module-name"].(string)
	if moduleName == "" {
		moduleName = "list-all"
	}

	// Create Azure credential using default credential chain
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure credential: %w", err)
	}

	// Get all subscriptions
	subscriptions, err := m.listSubscriptions(ctx, cred)
	if err != nil {
		return nil, fmt.Errorf("failed to list subscriptions: %w", err)
	}

	if cfg.Verbose {
		fmt.Fprintf(cfg.Output, "Found %d subscriptions\n", len(subscriptions))
	}

	// Query resources across all subscriptions
	resources, err := m.queryResources(ctx, cred, subscriptions)
	if err != nil {
		return nil, fmt.Errorf("failed to query resources: %w", err)
	}

	if cfg.Verbose {
		fmt.Fprintf(cfg.Output, "Found %d resources\n", len(resources))
	}

	// Return aggregated results
	return []plugin.Result{
		{
			Data: map[string]any{
				"subscriptions": subscriptions,
				"resources":     resources,
				"module_name":   moduleName,
			},
			Metadata: map[string]any{
				"subscription_count": len(subscriptions),
				"resource_count":     len(resources),
			},
		},
	}, nil
}

// listSubscriptions retrieves all accessible Azure subscriptions
func (m *ListAllResources) listSubscriptions(ctx context.Context, cred *azidentity.DefaultAzureCredential) ([]string, error) {
	client, err := armsubscriptions.NewClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create subscriptions client: %w", err)
	}

	var subscriptions []string
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get subscriptions page: %w", err)
		}

		for _, sub := range page.Value {
			if sub.SubscriptionID != nil {
				subscriptions = append(subscriptions, *sub.SubscriptionID)
			}
		}
	}

	return subscriptions, nil
}

// queryResources queries all resources across the provided subscriptions using Resource Graph
func (m *ListAllResources) queryResources(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptions []string) ([]map[string]any, error) {
	client, err := armresourcegraph.NewClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource graph client: %w", err)
	}

	// Query all resources across subscriptions
	query := "Resources | project id, name, type, location, resourceGroup, subscriptionId, tags, properties"

	request := armresourcegraph.QueryRequest{
		Query:         &query,
		Subscriptions: subscriptionsToPointers(subscriptions),
	}

	resp, err := client.Resources(ctx, request, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to query resources: %w", err)
	}

	// Parse the response data
	data, ok := resp.Data.([]any)
	if !ok {
		return nil, fmt.Errorf("unexpected response data type: %T", resp.Data)
	}

	var resources []map[string]any
	for _, item := range data {
		// Convert each item to map
		jsonBytes, err := json.Marshal(item)
		if err != nil {
			continue
		}

		var resource map[string]any
		if err := json.Unmarshal(jsonBytes, &resource); err != nil {
			continue
		}

		resources = append(resources, resource)
	}

	return resources, nil
}

// subscriptionsToPointers converts string slice to pointer slice
func subscriptionsToPointers(subs []string) []*string {
	result := make([]*string, len(subs))
	for i := range subs {
		result[i] = &subs[i]
	}
	return result
}
