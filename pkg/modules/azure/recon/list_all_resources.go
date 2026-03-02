package recon

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"

	azurehelpers "github.com/praetorian-inc/aurelian/internal/helpers/azure"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AzureListAllResourcesModule{})
}

// ListAllConfig holds parameters for the Azure list-all module.
type ListAllConfig struct {
	plugin.AzureCommonRecon
}

// AzureListAllResourcesModule enumerates all Azure resources via Resource Graph.
type AzureListAllResourcesModule struct {
	ListAllConfig
}

func (m *AzureListAllResourcesModule) ID() string                { return "list-all" }
func (m *AzureListAllResourcesModule) Name() string              { return "Azure List All Resources" }
func (m *AzureListAllResourcesModule) Platform() plugin.Platform { return plugin.PlatformAzure }
func (m *AzureListAllResourcesModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AzureListAllResourcesModule) OpsecLevel() string        { return "stealth" }
func (m *AzureListAllResourcesModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AzureListAllResourcesModule) Description() string {
	return "List all Azure resources across subscriptions using Azure Resource Graph. Supports scanning specific subscriptions or all accessible subscriptions."
}

func (m *AzureListAllResourcesModule) References() []string {
	return []string{
		"https://learn.microsoft.com/en-us/azure/azure-resource-graph/overview",
		"https://learn.microsoft.com/en-us/azure/governance/resource-graph/concepts/query-language",
	}
}

func (m *AzureListAllResourcesModule) SupportedResourceTypes() []string {
	return []string{"Azure::Resources::Resource"}
}

func (m *AzureListAllResourcesModule) Parameters() any {
	return &m.ListAllConfig
}

func (m *AzureListAllResourcesModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.ListAllConfig
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	cred, err := azurehelpers.NewAzureCredential()
	if err != nil {
		return fmt.Errorf("azure authentication failed: %w", err)
	}

	subs, err := azurehelpers.ResolveSubscriptions(ctx, cred, c.SubscriptionID)
	if err != nil {
		return fmt.Errorf("failed to resolve subscriptions: %w", err)
	}

	for _, sub := range subs {
		if err := querySubscription(ctx, cred, sub, out); err != nil {
			return fmt.Errorf("failed to query subscription %s: %w", sub, err)
		}
	}

	return nil
}

func querySubscription(ctx context.Context, cred azcore.TokenCredential, subscriptionID string, out *pipeline.P[model.AurelianModel]) error {
	client, err := armresourcegraph.NewClient(cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create resource graph client: %w", err)
	}

	query := "Resources | project id, name, type, location, resourceGroup, tags, properties = pack_all()"
	request := armresourcegraph.QueryRequest{
		Query:         &query,
		Subscriptions: []*string{&subscriptionID},
		Options: &armresourcegraph.QueryRequestOptions{
			Top:          to.Ptr(int32(1000)),
			ResultFormat: to.Ptr(armresourcegraph.ResultFormatObjectArray),
		},
	}

	for {
		resp, err := client.Resources(ctx, request, nil)
		if err != nil {
			return fmt.Errorf("resource graph query failed: %w", err)
		}

		rows, ok := resp.Data.([]any)
		if !ok {
			return fmt.Errorf("unexpected response data type: %T", resp.Data)
		}

		for _, row := range rows {
			resource, err := parseARGRow(row, subscriptionID)
			if err != nil {
				continue
			}
			out.Send(resource)
		}

		if resp.SkipToken == nil || *resp.SkipToken == "" {
			break
		}
		request.Options.SkipToken = resp.SkipToken
	}

	return nil
}

func parseARGRow(row any, subscriptionID string) (output.AzureResource, error) {
	rowMap, ok := row.(map[string]any)
	if !ok {
		return output.AzureResource{}, fmt.Errorf("unexpected row type: %T", row)
	}

	resource := output.NewAzureResource(
		subscriptionID,
		stringFromMap(rowMap, "type"),
		stringFromMap(rowMap, "id"),
	)
	resource.DisplayName = stringFromMap(rowMap, "name")
	resource.Location = stringFromMap(rowMap, "location")
	resource.ResourceGroup = stringFromMap(rowMap, "resourceGroup")

	if tags, ok := rowMap["tags"]; ok && tags != nil {
		if tagMap, ok := tags.(map[string]any); ok {
			resource.Tags = make(map[string]string, len(tagMap))
			for k, v := range tagMap {
				if s, ok := v.(string); ok {
					resource.Tags[k] = s
				}
			}
		}
	}

	if props, ok := rowMap["properties"]; ok && props != nil {
		if propMap, ok := props.(map[string]any); ok {
			resource.Properties = propMap
		} else {
			data, err := json.Marshal(props)
			if err == nil {
				var m map[string]any
				if json.Unmarshal(data, &m) == nil {
					resource.Properties = m
				}
			}
		}
	}

	return resource, nil
}

func stringFromMap(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
