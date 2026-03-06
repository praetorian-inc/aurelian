package recon

import (
	"fmt"
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
