package resourcegraph

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"

	azurehelpers "github.com/praetorian-inc/aurelian/internal/helpers/azure"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

const listAllQuery = "Resources | project id, name, type, location, resourceGroup, tags, properties"

// Options configures the ResourceGraphLister behavior.
type Options struct {
	PageSize int32 // Maximum results per ARG request. Defaults to 1000 if <= 0.
}

// ResourceGraphLister enumerates Azure resources via the Resource Graph API.
type ResourceGraphLister struct {
	client  *armresourcegraph.Client
	options Options
}

// NewResourceGraphLister creates a lister with an initialized ARG client.
// Pass nil for opts to use defaults.
func NewResourceGraphLister(cred azcore.TokenCredential, opts *Options) (*ResourceGraphLister, error) {
	client, err := armresourcegraph.NewClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource graph client: %w", err)
	}
	o := Options{PageSize: 1000}
	if opts != nil && opts.PageSize > 0 {
		o = *opts
	}
	return &ResourceGraphLister{client: client, options: o}, nil
}

// ListAll enumerates all resources across the given subscriptions using the
// default KQL query, emitting each as an AzureResource into out.
func (l *ResourceGraphLister) ListAll(ctx context.Context, subs []azurehelpers.SubscriptionInfo, out *pipeline.P[model.AurelianModel]) error {
	return l.List(ctx, subs, listAllQuery, out)
}

// List runs a custom KQL query across the given subscriptions, emitting each
// result as an AzureResource into out.
func (l *ResourceGraphLister) List(ctx context.Context, subs []azurehelpers.SubscriptionInfo, query string, out *pipeline.P[model.AurelianModel]) error {
	for _, sub := range subs {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := l.querySubscription(ctx, sub, query, out); err != nil {
			return fmt.Errorf("failed to query subscription %s: %w", sub.ID, err)
		}
	}
	return nil
}

func (l *ResourceGraphLister) querySubscription(ctx context.Context, sub azurehelpers.SubscriptionInfo, query string, out *pipeline.P[model.AurelianModel]) error {
	request := armresourcegraph.QueryRequest{
		Query:         &query,
		Subscriptions: []*string{&sub.ID},
		Options: &armresourcegraph.QueryRequestOptions{
			Top:          to.Ptr(l.options.PageSize),
			ResultFormat: to.Ptr(armresourcegraph.ResultFormatObjectArray),
		},
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		resp, err := l.client.Resources(ctx, request, nil)
		if err != nil {
			return fmt.Errorf("resource graph query failed: %w", err)
		}

		rows, ok := resp.Data.([]any)
		if !ok {
			return fmt.Errorf("unexpected response data type: %T", resp.Data)
		}

		for _, row := range rows {
			resource, err := parseARGRow(row, sub)
			if err != nil {
				slog.Debug("skipping malformed ARG row", "error", err)
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

func parseARGRow(row any, sub azurehelpers.SubscriptionInfo) (output.AzureResource, error) {
	rowMap, ok := row.(map[string]any)
	if !ok {
		return output.AzureResource{}, fmt.Errorf("unexpected row type: %T", row)
	}

	resource := output.NewAzureResource(
		sub.ID,
		stringFromMap(rowMap, "type"),
		stringFromMap(rowMap, "id"),
	)
	resource.SubscriptionName = sub.DisplayName
	resource.TenantID = sub.TenantID
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

	// Capture any additional projected fields (e.g. from extend/project) into Properties.
	for k, v := range rowMap {
		switch k {
		case "id", "name", "type", "location", "resourceGroup", "tags", "properties", "subscriptionId":
			continue
		default:
			if resource.Properties == nil {
				resource.Properties = make(map[string]any)
			}
			resource.Properties[k] = v
		}
	}

	if resource.Properties != nil {
		tryUnmarshalJSONStrings(resource.Properties)
	}

	return resource, nil
}

// tryUnmarshalJSONStrings walks a map and replaces string values that are
// valid JSON objects or arrays with their unmarshaled form.
func tryUnmarshalJSONStrings(m map[string]any) {
	for k, v := range m {
		s, ok := v.(string)
		if !ok || len(s) < 2 {
			continue
		}
		if (s[0] == '{' && s[len(s)-1] == '}') || (s[0] == '[' && s[len(s)-1] == ']') {
			var parsed any
			if json.Unmarshal([]byte(s), &parsed) == nil {
				m[k] = parsed
			}
		}
	}
}

func stringFromMap(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
