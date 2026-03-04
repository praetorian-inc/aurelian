package subscriptions

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	azuretypes "github.com/praetorian-inc/aurelian/pkg/azure/types"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

type SubscriptionResolver struct {
	cred azcore.TokenCredential
}

func NewSubscriptionResolver(cred azcore.TokenCredential) *SubscriptionResolver {
	resolver := &SubscriptionResolver{cred: cred}
	return resolver
}

func (r *SubscriptionResolver) Resolve(id string, out *pipeline.P[azuretypes.SubscriptionInfo]) error {
	sub, err := r.getByID(id)
	if err != nil {
		return err
	}

	out.Send(sub)
	return nil
}

func (r *SubscriptionResolver) getByID(id string) (azuretypes.SubscriptionInfo, error) {
	client, err := r.newClient()
	if err != nil {
		return azuretypes.SubscriptionInfo{}, err
	}

	resp, err := client.Get(context.Background(), id, nil)
	if err != nil {
		return azuretypes.SubscriptionInfo{}, fmt.Errorf("failed to get subscription %s: %w", id, err)
	}

	return fromSDK(&resp.Subscription), nil
}

func (r *SubscriptionResolver) ListAllSubscriptions() ([]azuretypes.SubscriptionInfo, error) {
	client, err := r.newClient()
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(nil)
	subs := []azuretypes.SubscriptionInfo{}
	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to list subscriptions: %w", err)
		}

		for _, sub := range page.Value {
			if sub.SubscriptionID == nil {
				continue
			}
			subs = append(subs, fromSDK(sub))
		}
	}

	return subs, nil
}

func (r *SubscriptionResolver) newClient() (*armsubscriptions.Client, error) {
	client, err := armsubscriptions.NewClient(r.cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create subscriptions client: %w", err)
	}
	return client, nil
}

func fromSDK(sub *armsubscriptions.Subscription) azuretypes.SubscriptionInfo {
	info := azuretypes.SubscriptionInfo{}
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
