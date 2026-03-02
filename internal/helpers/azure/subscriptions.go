package azure

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
)

// SubscriptionInfo holds metadata about an Azure subscription.
type SubscriptionInfo struct {
	ID          string
	DisplayName string
	TenantID    string
}

// ResolveSubscriptions returns subscription info for the given IDs. If ids
// contains "all", it enumerates all accessible subscriptions. Otherwise it
// looks up each ID to populate display name and tenant ID.
func ResolveSubscriptions(ctx context.Context, cred azcore.TokenCredential, ids []string) ([]SubscriptionInfo, error) {
	if len(ids) == 1 && strings.EqualFold(ids[0], "all") {
		return ListSubscriptions(ctx, cred)
	}
	return getSubscriptions(ctx, cred, ids)
}

// ListSubscriptions enumerates all accessible Azure subscriptions.
func ListSubscriptions(ctx context.Context, cred azcore.TokenCredential) ([]SubscriptionInfo, error) {
	if cred == nil {
		return nil, fmt.Errorf("credential is required to list subscriptions")
	}

	client, err := armsubscriptions.NewClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create subscriptions client: %w", err)
	}

	var subs []SubscriptionInfo
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
				subs = append(subs, subscriptionFromSDK(sub))
			}
		}
	}

	if len(subs) == 0 {
		return nil, fmt.Errorf("no accessible subscriptions found")
	}

	return subs, nil
}

// getSubscriptions looks up each subscription ID to populate metadata.
func getSubscriptions(ctx context.Context, cred azcore.TokenCredential, ids []string) ([]SubscriptionInfo, error) {
	if cred == nil {
		subs := make([]SubscriptionInfo, len(ids))
		for i, id := range ids {
			subs[i] = SubscriptionInfo{ID: id}
		}
		return subs, nil
	}

	client, err := armsubscriptions.NewClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create subscriptions client: %w", err)
	}

	subs := make([]SubscriptionInfo, 0, len(ids))
	for _, id := range ids {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		resp, err := client.Get(ctx, id, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to get subscription %s: %w", id, err)
		}
		subs = append(subs, subscriptionFromSDK(&resp.Subscription))
	}
	return subs, nil
}

func subscriptionFromSDK(sub *armsubscriptions.Subscription) SubscriptionInfo {
	info := SubscriptionInfo{}
	if sub.SubscriptionID != nil {
		info.ID = *sub.SubscriptionID
	}
	if sub.DisplayName != nil {
		info.DisplayName = *sub.DisplayName
	}
	if sub.TenantID != nil {
		info.TenantID = *sub.TenantID
	}
	return info
}
