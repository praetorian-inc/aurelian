package iam

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBatchPermissions_Empty(t *testing.T) {
	batches := batchPermissions(nil, 100)
	assert.Nil(t, batches)

	batches = batchPermissions([]string{}, 100)
	assert.Nil(t, batches)
}

func TestBatchPermissions_SmallerThanBatchSize(t *testing.T) {
	perms := []string{"a", "b", "c"}
	batches := batchPermissions(perms, 100)
	require.Len(t, batches, 1)
	assert.Equal(t, perms, batches[0])
}

func TestBatchPermissions_ExactlyBatchSize(t *testing.T) {
	perms := make([]string, 100)
	for i := range perms {
		perms[i] = fmt.Sprintf("perm-%d", i)
	}
	batches := batchPermissions(perms, 100)
	require.Len(t, batches, 1)
	assert.Len(t, batches[0], 100)
}

func TestBatchPermissions_LargerThanBatchSize(t *testing.T) {
	perms := make([]string, 250)
	for i := range perms {
		perms[i] = fmt.Sprintf("perm-%d", i)
	}
	batches := batchPermissions(perms, 100)
	require.Len(t, batches, 3)
	assert.Len(t, batches[0], 100)
	assert.Len(t, batches[1], 100)
	assert.Len(t, batches[2], 50)

	// Verify all permissions are present and in order.
	var all []string
	for _, b := range batches {
		all = append(all, b...)
	}
	assert.Equal(t, perms, all)
}
