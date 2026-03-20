package azure

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveSubscriptions_SpecificIDs(t *testing.T) {
	ids := []string{"sub-aaa", "sub-bbb"}
	result, err := ResolveSubscriptions(context.Background(), nil, ids)
	require.NoError(t, err)
	assert.Len(t, result, 2)
	assert.Equal(t, "sub-aaa", result[0].ID)
	assert.Equal(t, "sub-bbb", result[1].ID)
}

func TestResolveSubscriptions_SpecificIDs_NoCredential(t *testing.T) {
	ids := []string{"sub-aaa"}
	result, err := ResolveSubscriptions(context.Background(), nil, ids)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "sub-aaa", result[0].ID)
	assert.Empty(t, result[0].DisplayName)
	assert.Empty(t, result[0].TenantID)
}

func TestResolveSubscriptions_AllRequiresCredential(t *testing.T) {
	_, err := ResolveSubscriptions(context.Background(), nil, []string{"all"})
	assert.Error(t, err, "should fail when credential is nil and 'all' is requested")
}
