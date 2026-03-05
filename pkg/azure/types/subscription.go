package types

type SubscriptionInfo struct {
	ID          string
	DisplayName string
	TenantID    string
}

// SubscriptionQuery pairs a resolved subscription with resource type filters
// for use in pipeline stages that need both subscription context and type filtering.
type SubscriptionQuery struct {
	Subscription  SubscriptionInfo
	ResourceTypes []string
}
