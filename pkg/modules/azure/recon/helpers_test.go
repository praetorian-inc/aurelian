package recon

import (
	"fmt"
	"testing"

	azuretypes "github.com/praetorian-inc/aurelian/pkg/azure/types"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockResolver struct {
	subs []azuretypes.SubscriptionInfo
	err  error
}

func (m *mockResolver) Resolve(id string, out *pipeline.P[azuretypes.SubscriptionInfo]) error {
	for _, s := range m.subs {
		if s.ID == id {
			out.Send(s)
			return nil
		}
	}
	return fmt.Errorf("subscription %s not found", id)
}

func (m *mockResolver) ListAllSubscriptions() ([]azuretypes.SubscriptionInfo, error) {
	return m.subs, m.err
}

func TestResolveSubscriptionIDs_SpecificIDs(t *testing.T) {
	resolver := &mockResolver{}
	ids, err := resolveSubscriptionIDs([]string{"sub-1", "sub-2"}, resolver)
	require.NoError(t, err)
	assert.Equal(t, []string{"sub-1", "sub-2"}, ids)
}

func TestResolveSubscriptionIDs_All(t *testing.T) {
	resolver := &mockResolver{
		subs: []azuretypes.SubscriptionInfo{
			{ID: "sub-1", DisplayName: "Sub 1"},
			{ID: "sub-2", DisplayName: "Sub 2"},
		},
	}
	ids, err := resolveSubscriptionIDs([]string{"all"}, resolver)
	require.NoError(t, err)
	assert.Equal(t, []string{"sub-1", "sub-2"}, ids)
}

func TestResolveSubscriptionIDs_AllCaseInsensitive(t *testing.T) {
	resolver := &mockResolver{
		subs: []azuretypes.SubscriptionInfo{{ID: "sub-1"}},
	}
	ids, err := resolveSubscriptionIDs([]string{"ALL"}, resolver)
	require.NoError(t, err)
	assert.Equal(t, []string{"sub-1"}, ids)
}

func TestResolveSubscriptionIDs_AllError(t *testing.T) {
	resolver := &mockResolver{err: fmt.Errorf("auth failed")}
	_, err := resolveSubscriptionIDs([]string{"all"}, resolver)
	assert.Error(t, err)
}
