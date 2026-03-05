package recon

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/azure/subscriptions"
)

// resolveSubscriptionIDs returns the given IDs as-is unless the sole entry is
// "all", in which case it lists every accessible subscription.
func resolveSubscriptionIDs(ids []string, resolver *subscriptions.SubscriptionResolver) ([]string, error) {
	if len(ids) != 1 || !strings.EqualFold(ids[0], "all") {
		return ids, nil
	}

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
