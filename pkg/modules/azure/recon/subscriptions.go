package recon

import (
	"fmt"
	"strings"

	azuretypes "github.com/praetorian-inc/aurelian/pkg/azure/types"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

type subscriptionResolver interface {
	Resolve(id string, out *pipeline.P[azuretypes.SubscriptionInfo]) error
	ListAllSubscriptions() ([]azuretypes.SubscriptionInfo, error)
}

// resolveSubscriptionIDs expands subscription IDs, resolving "all" to every accessible subscription.
func resolveSubscriptionIDs(ids []string, resolver subscriptionResolver) ([]string, error) {
	requestsAllSubscriptions := len(ids) == 1 && strings.EqualFold(ids[0], "all")
	if !requestsAllSubscriptions {
		return ids, nil
	}

	subs, err := resolver.ListAllSubscriptions()
	if err != nil {
		return nil, fmt.Errorf("failed to list subscriptions: %w", err)
	}

	resolvedIDs := make([]string, 0, len(subs))
	for _, sub := range subs {
		resolvedIDs = append(resolvedIDs, sub.ID)
	}
	return resolvedIDs, nil
}
