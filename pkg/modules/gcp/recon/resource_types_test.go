package recon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveResourceTypes_All(t *testing.T) {
	types, err := resolveResourceTypes([]string{"all"})
	require.NoError(t, err)
	assert.Greater(t, len(types), 10)
}

func TestResolveResourceTypes_ByAlias(t *testing.T) {
	types, err := resolveResourceTypes([]string{"vm", "bucket"})
	require.NoError(t, err)
	assert.Contains(t, types, "compute.googleapis.com/Instance")
	assert.Contains(t, types, "storage.googleapis.com/Bucket")
	assert.Len(t, types, 2)
}

func TestResolveResourceTypes_ByCanonicalName(t *testing.T) {
	types, err := resolveResourceTypes([]string{"compute.googleapis.com/Instance"})
	require.NoError(t, err)
	assert.Equal(t, []string{"compute.googleapis.com/Instance"}, types)
}

func TestResolveResourceTypes_InvalidType(t *testing.T) {
	_, err := resolveResourceTypes([]string{"nonexistent"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported resource type")
}

func TestValidateResourceTypes(t *testing.T) {
	assert.NoError(t, validateResourceTypes([]string{"vm", "bucket"}))
	assert.NoError(t, validateResourceTypes([]string{"all"}))
	assert.Error(t, validateResourceTypes([]string{"bogus"}))
}
