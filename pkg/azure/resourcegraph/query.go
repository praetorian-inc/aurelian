package resourcegraph

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

const defaultPageSize int32 = 1000

// queryARG executes an ARG query against the given subscriptions with pagination.
// Each result row (map[string]any) is passed to handleRow.
func queryARG(
	cred azcore.TokenCredential,
	query string,
	subscriptionIDs []string,
	pageSize int32,
	handleRow func(row map[string]any) error,
) error {
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}

	subPtrs := make([]*string, len(subscriptionIDs))
	for i := range subscriptionIDs {
		subPtrs[i] = &subscriptionIDs[i]
	}

	request := armresourcegraph.QueryRequest{
		Query:         &query,
		Subscriptions: subPtrs,
		Options: &armresourcegraph.QueryRequestOptions{
			Top:          to.Ptr(pageSize),
			ResultFormat: to.Ptr(armresourcegraph.ResultFormatObjectArray),
		},
	}

	client, err := armresourcegraph.NewClient(cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create resource graph client: %w", err)
	}

	paginator := ratelimit.NewPaginator()
	return paginator.Paginate(func() (bool, error) {
		resp, err := client.Resources(context.Background(), request, nil)
		if err != nil {
			return false, fmt.Errorf("resource graph query failed: %w", err)
		}

		rows, ok := resp.Data.([]any)
		if !ok {
			return false, fmt.Errorf("unexpected response data type: %T", resp.Data)
		}

		for _, row := range rows {
			rowMap, ok := row.(map[string]any)
			if !ok {
				continue
			}
			if err := handleRow(rowMap); err != nil {
				return false, err
			}
		}

		hasMorePages := resp.SkipToken != nil && *resp.SkipToken != ""
		if hasMorePages {
			request.Options.SkipToken = resp.SkipToken
		}
		return hasMorePages, nil
	})
}
