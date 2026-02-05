package helpers

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
)

// ARGQueryOptions represents options for executing an ARG query
type ARGQueryOptions struct {
	// Subscriptions to query. If nil, queries all accessible subscriptions
	Subscriptions []string
	// Maximum number of records to return. If 0, uses default (100)
	Top int32
	// Skip first N records
	Skip int32
	// Format for the results (defaults to ObjectArray)
	ResultFormat armresourcegraph.ResultFormat
}

// ARGClient wraps the ARG client for easier use
type ARGClient struct {
	client *armresourcegraph.Client
	logger *slog.Logger
}

// NewARGClient creates a new ARG client using default credentials
func NewARGClient(ctx context.Context) (*ARGClient, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %v", err)
	}

	client, err := armresourcegraph.NewClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create ARG client: %v", err)
	}

	return &ARGClient{
		client: client,
		logger: slog.Default().With("component", "ARGClient"),
	}, nil
}

// ExecuteQuery runs an ARG query with the given options
func (c *ARGClient) ExecuteQuery(ctx context.Context, query string, opts *ARGQueryOptions) (*armresourcegraph.ClientResourcesResponse, error) {
	if opts == nil {
		opts = &ARGQueryOptions{
			ResultFormat: armresourcegraph.ResultFormatObjectArray,
		}
	}

	// Build request options
	options := &armresourcegraph.QueryRequestOptions{
		ResultFormat: to.Ptr(opts.ResultFormat),
	}
	if opts.Top > 0 {
		options.Top = to.Ptr(opts.Top)
	}
	if opts.Skip > 0 {
		options.Skip = to.Ptr(opts.Skip)
	}

	// Convert subscription slice to pointer slice
	var subPtrs []*string
	if opts.Subscriptions != nil {
		for _, sub := range opts.Subscriptions {
			subCopy := sub
			subPtrs = append(subPtrs, &subCopy)
		}
	}

	request := armresourcegraph.QueryRequest{
		Query:         &query,
		Options:       options,
		Subscriptions: subPtrs,
	}

	response, err := c.client.Resources(ctx, request, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to execute ARG query: %v", err)
	}

	return &response, nil
}

// ExecutePaginatedQuery executes an ARG query and handles pagination automatically
func (c *ARGClient) ExecutePaginatedQuery(ctx context.Context, query string, opts *ARGQueryOptions, callback func(response *armresourcegraph.ClientResourcesResponse) error) error {
	if opts == nil {
		opts = &ARGQueryOptions{
			ResultFormat: armresourcegraph.ResultFormatObjectArray,
		}
	}

	var skip int32 = 0
	for {
		// Update skip value in options
		currentOpts := *opts
		currentOpts.Skip = skip

		// Execute query
		response, err := c.ExecuteQuery(ctx, query, &currentOpts)
		if err != nil {
			return err
		}

		// Process results
		if err := callback(response); err != nil {
			return err
		}

		// Check if we've processed all results
		if response.TotalRecords == nil || response.Count == nil ||
			int64(skip) >= *response.TotalRecords || *response.Count == 0 {
			break
		}

		skip += int32(*response.Count)
	}

	return nil
}

// Common ARG Queries
const (
	QueryResourcesByType = "Resources | summarize count=count() by type, location | order by type asc"

	QueryResourcesByLocation = "Resources | summarize count=count() by location, type | order by location asc"

	QueryResourcesWithTags = "Resources | where tags != '' | project name, type, tags, location"
)

// Helper functions for common queries
func (c *ARGClient) GetResourceSummaryByType(ctx context.Context, subscriptionID string) (*armresourcegraph.ClientResourcesResponse, error) {
	query := QueryResourcesByType
	if subscriptionID != "" {
		query = fmt.Sprintf("Resources | where subscriptionId == '%s' | summarize count=count() by type, location | order by type asc", subscriptionID)
	}

	return c.ExecuteQuery(ctx, query, &ARGQueryOptions{
		ResultFormat:  armresourcegraph.ResultFormatObjectArray,
		Subscriptions: []string{subscriptionID},
	})
}

func (c *ARGClient) GetResourceSummaryByLocation(ctx context.Context, subscriptionID string) (*armresourcegraph.ClientResourcesResponse, error) {
	query := QueryResourcesByLocation
	if subscriptionID != "" {
		query = fmt.Sprintf("Resources | where subscriptionId == '%s' | summarize count=count() by location, type | order by location asc", subscriptionID)
	}

	return c.ExecuteQuery(ctx, query, &ARGQueryOptions{
		ResultFormat:  armresourcegraph.ResultFormatObjectArray,
		Subscriptions: []string{subscriptionID},
	})
}

// ProcessQueryResponse processes a query response into a map of resource types to counts
func ProcessQueryResponse(response *armresourcegraph.ClientResourcesResponse) (map[string]int, error) {
	resourceMap := make(map[string]int)

	if response == nil || response.Data == nil {
		return resourceMap, nil
	}

	// Parse the response data
	for _, row := range response.Data.([]interface{}) {
		item := row.(map[string]interface{})
		resourceType := item["type"].(string)
		count := int(item["count"].(float64))
		resourceMap[resourceType] += count
	}

	return resourceMap, nil
}
