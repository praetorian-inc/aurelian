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
	assert.Equal(t, ids, result)
}

func TestResolveSubscriptions_AllRequiresCredential(t *testing.T) {
	_, err := ResolveSubscriptions(context.Background(), nil, []string{"all"})
	assert.Error(t, err, "should fail when credential is nil and 'all' is requested")
}
