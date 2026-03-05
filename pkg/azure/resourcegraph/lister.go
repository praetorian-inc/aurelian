package resourcegraph

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	azuretypes "github.com/praetorian-inc/aurelian/pkg/azure/types"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

const listAllQuery = "Resources | project id, name, type, location, resourceGroup, tags, properties"

// Options configures the ResourceGraphLister behavior.
type Options struct {
	PageSize int32 // Maximum results per ARG request. Defaults to 1000 if <= 0.
}

// ResourceGraphLister enumerates Azure resources via the Resource Graph API.
type ResourceGraphLister struct {
	cred    azcore.TokenCredential
	options Options
}

// NewResourceGraphLister creates a lister. Pass nil for opts to use defaults.
func NewResourceGraphLister(cred azcore.TokenCredential, opts *Options) *ResourceGraphLister {
	o := Options{PageSize: 1000}
	if opts != nil && opts.PageSize > 0 {
		o = *opts
	}

	lister := &ResourceGraphLister{cred: cred, options: o}
	return lister
}

// QueryTemplateInput pairs a subscription with a template for querying.
type QueryTemplateInput struct {
	Subscription azuretypes.SubscriptionInfo
	Template     *templates.ARGQueryTemplate
}

// QueryTemplate executes an ARG query template against a subscription and emits results.
func (l *ResourceGraphLister) QueryTemplate(input QueryTemplateInput, out *pipeline.P[templates.ARGQueryResult]) error {
	query := input.Template.Query
	sub := input.Subscription

	request := armresourcegraph.QueryRequest{
		Query:         &query,
		Subscriptions: []*string{&sub.ID},
		Options: &armresourcegraph.QueryRequestOptions{
			Top:          to.Ptr(l.options.PageSize),
			ResultFormat: to.Ptr(armresourcegraph.ResultFormatObjectArray),
		},
	}

	paginator := ratelimit.NewPaginator()
	return paginator.Paginate(func() (bool, error) {
		resp, err := l.queryResources(request)
		if err != nil {
			return false, fmt.Errorf("resource graph query failed for template %s: %w", input.Template.ID, err)
		}

		rows, ok := resp.Data.([]any)
		if !ok {
			return false, fmt.Errorf("unexpected response data type: %T", resp.Data)
		}

		for _, row := range rows {
			result, parseErr := parseARGTemplateRow(row, input.Template)
			if parseErr != nil {
				slog.Debug("skipping malformed ARG template row", "template", input.Template.ID, "error", parseErr)
				continue
			}
			result.SubscriptionID = sub.ID
			out.Send(result)
		}

		hasMorePages := resp.SkipToken != nil && *resp.SkipToken != ""
		if hasMorePages {
			request.Options.SkipToken = resp.SkipToken
		}
		return hasMorePages, nil
	})
}

// ListAll enumerates all resources for a subscription using the default KQL query.
func (l *ResourceGraphLister) ListAll(sub azuretypes.SubscriptionInfo, out *pipeline.P[model.AurelianModel]) error {
	err := l.querySubscription(sub, listAllQuery, out)
	if err != nil {
		return fmt.Errorf("failed to query subscription %s: %w", sub.ID, err)
	}

	return nil
}

func (l *ResourceGraphLister) querySubscription(sub azuretypes.SubscriptionInfo, query string, out *pipeline.P[model.AurelianModel]) error {
	request := armresourcegraph.QueryRequest{
		Query:         &query,
		Subscriptions: []*string{&sub.ID},
		Options: &armresourcegraph.QueryRequestOptions{
			Top:          to.Ptr(l.options.PageSize),
			ResultFormat: to.Ptr(armresourcegraph.ResultFormatObjectArray),
		},
	}

	paginator := ratelimit.NewPaginator()
	return paginator.Paginate(func() (bool, error) {
		resp, err := l.queryResources(request)
		if err != nil {
			return false, fmt.Errorf("resource graph query failed: %w", err)
		}

		rows, ok := resp.Data.([]any)
		if !ok {
			return false, fmt.Errorf("unexpected response data type: %T", resp.Data)
		}

		for _, row := range rows {
			resource, parseErr := parseARGRow(row, sub)
			if parseErr != nil {
				slog.Debug("skipping malformed ARG row", "error", parseErr)
				continue
			}
			out.Send(resource)
		}

		hasMorePages := resp.SkipToken != nil && *resp.SkipToken != ""
		if hasMorePages {
			request.Options.SkipToken = resp.SkipToken
		}
		return hasMorePages, nil
	})
}

func (l *ResourceGraphLister) queryResources(request armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
	client, err := armresourcegraph.NewClient(l.cred, nil)
	if err != nil {
		return armresourcegraph.ClientResourcesResponse{}, fmt.Errorf("failed to create resource graph client: %w", err)
	}
	return client.Resources(context.Background(), request, nil)
}

func parseARGRow(row any, sub azuretypes.SubscriptionInfo) (output.AzureResource, error) {
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
				s, valueIsString := v.(string)
				if !valueIsString {
					continue
				}
				resource.Tags[k] = s
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

// parseARGTemplateRow converts a raw ARG response row into an ARGQueryResult.
// Standard fields (id, name, type, location, subscriptionId) are extracted;
// all other projected columns go into Properties.
func parseARGTemplateRow(row any, tmpl *templates.ARGQueryTemplate) (templates.ARGQueryResult, error) {
	rowMap, ok := row.(map[string]any)
	if !ok {
		return templates.ARGQueryResult{}, fmt.Errorf("unexpected row type: %T", row)
	}

	result := templates.ARGQueryResult{
		TemplateID:      tmpl.ID,
		TemplateDetails: tmpl,
		ResourceID:      stringFromMap(rowMap, "id"),
		ResourceName:    stringFromMap(rowMap, "name"),
		ResourceType:    stringFromMap(rowMap, "type"),
		Location:        stringFromMap(rowMap, "location"),
		SubscriptionID:  stringFromMap(rowMap, "subscriptionId"),
		Name:            tmpl.Name,
	}

	props := make(map[string]any)
	for k, v := range rowMap {
		switch k {
		case "id", "name", "type", "location", "subscriptionId":
			continue
		default:
			props[k] = v
		}
	}
	if len(props) > 0 {
		tryUnmarshalJSONStrings(props)
		result.Properties = props
	}

	return result, nil
}

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
	v, ok := m[key]
	if !ok {
		return ""
	}

	s, ok := v.(string)
	if !ok {
		return ""
	}

	return s
}
