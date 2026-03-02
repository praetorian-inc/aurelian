package resourcegraph

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

const listAllQuery = "Resources | project id, name, type, location, resourceGroup, tags, properties"

// ResourceGraphLister enumerates Azure resources via the Resource Graph API.
type ResourceGraphLister struct {
	client *armresourcegraph.Client
}

// NewResourceGraphLister creates a lister with an initialized ARG client.
func NewResourceGraphLister(cred azcore.TokenCredential) (*ResourceGraphLister, error) {
	client, err := armresourcegraph.NewClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource graph client: %w", err)
	}
	return &ResourceGraphLister{client: client}, nil
}

// List enumerates all resources across the given subscriptions, emitting each
// as an AzureResource into out.
func (l *ResourceGraphLister) List(ctx context.Context, subscriptionIDs []string, out *pipeline.P[model.AurelianModel]) error {
	for _, sub := range subscriptionIDs {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := l.querySubscription(ctx, sub, out); err != nil {
			return fmt.Errorf("failed to query subscription %s: %w", sub, err)
		}
	}
	return nil
}

func (l *ResourceGraphLister) querySubscription(ctx context.Context, subscriptionID string, out *pipeline.P[model.AurelianModel]) error {
	query := listAllQuery
	request := armresourcegraph.QueryRequest{
		Query:         &query,
		Subscriptions: []*string{&subscriptionID},
		Options: &armresourcegraph.QueryRequestOptions{
			Top:          to.Ptr(int32(1000)),
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
			resource, err := parseARGRow(row, subscriptionID)
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
