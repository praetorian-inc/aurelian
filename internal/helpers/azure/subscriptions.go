package azure

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
)

// ResolveSubscriptions returns a list of subscription IDs. If ids contains
// "all", it enumerates all accessible subscriptions using the provided credential.
// Otherwise it returns the provided IDs as-is.
func ResolveSubscriptions(ctx context.Context, cred azcore.TokenCredential, ids []string) ([]string, error) {
	if len(ids) == 1 && strings.EqualFold(ids[0], "all") {
		return ListSubscriptions(ctx, cred)
	}
	return ids, nil
}

// ListSubscriptions enumerates all accessible Azure subscriptions.
func ListSubscriptions(ctx context.Context, cred azcore.TokenCredential) ([]string, error) {
	if cred == nil {
		return nil, fmt.Errorf("credential is required to list subscriptions")
	}

	client, err := armsubscriptions.NewClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create subscriptions client: %w", err)
	}

	var subs []string
	pager := client.NewListPager(nil)
	for pager.More() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list subscriptions: %w", err)
		}
		for _, sub := range page.Value {
			if sub.SubscriptionID != nil {
				subs = append(subs, *sub.SubscriptionID)
			}
		}
	}

	if len(subs) == 0 {
		return nil, fmt.Errorf("no accessible subscriptions found")
	}

	return subs, nil
}
