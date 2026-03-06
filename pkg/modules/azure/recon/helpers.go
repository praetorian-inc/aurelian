package recon

import (
	"fmt"
	"github.com/praetorian-inc/aurelian/pkg/azure/resourcegraph"
	azuretypes "github.com/praetorian-inc/aurelian/pkg/azure/types"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"strings"
)

// resolveSubscriptionIDs returns the given IDs directly, or if ids is ["all"],
// lists all accessible subscriptions and returns their IDs.
func resolveSubscriptionIDs(ids []string, resolver subscriptionResolver) ([]string, error) {
	if len(ids) == 1 && strings.EqualFold(ids[0], "all") {
		subs, err := resolver.ListAllSubscriptions()
		if err != nil {
			return nil, fmt.Errorf("failed to list subscriptions: %w", err)
		}
		resolved := make([]string, 0, len(subs))
		for _, sub := range subs {
			resolved = append(resolved, sub.ID)
		}
		return resolved, nil
	}
	return ids, nil
}

func subscriptionToListerInput(sub azuretypes.SubscriptionInfo, out *pipeline.P[resourcegraph.ListerInput]) error {
	out.Send(resourcegraph.ListerInput{Subscription: sub})
	return nil
}

func toAurelianModel(r output.AzureResource, out *pipeline.P[model.AurelianModel]) error {
	out.Send(r)
	return nil
}
