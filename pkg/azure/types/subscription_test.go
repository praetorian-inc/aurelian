package types

import "testing"

func TestSubscriptionQuery(t *testing.T) {
	sub := SubscriptionInfo{ID: "sub-123", DisplayName: "Test", TenantID: "tenant-1"}
	q := SubscriptionQuery{
		Subscription:  sub,
		ResourceTypes: []string{"Microsoft.Compute/virtualMachines", "Microsoft.Web/sites"},
	}

	if q.Subscription.ID != "sub-123" {
		t.Errorf("expected sub-123, got %s", q.Subscription.ID)
	}
	if len(q.ResourceTypes) != 2 {
		t.Errorf("expected 2 resource types, got %d", len(q.ResourceTypes))
	}
}
