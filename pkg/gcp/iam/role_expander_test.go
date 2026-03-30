package iam

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRoleExpanderInitialState(t *testing.T) {
	re := &RoleExpander{}
	assert.Nil(t, re.rolePermissions)
	assert.Nil(t, re.initErr)
}

func TestRoleExpanderDeduplicatesAndSorts(t *testing.T) {
	// Pre-populate the cache so we don't need a real API call.
	re := &RoleExpander{
		rolePermissions: map[string][]string{
			"roles/viewer": {
				"storage.objects.get",
				"compute.instances.list",
				"storage.buckets.list",
			},
			"roles/editor": {
				"storage.objects.get", // duplicate with viewer
				"compute.instances.create",
				"storage.buckets.create",
			},
		},
	}
	// Mark as already initialised so once.Do is a no-op.
	re.once.Do(func() {})

	perms, err := re.Expand(context.Background(), []string{"roles/viewer", "roles/editor"})
	assert.NoError(t, err)

	expected := []string{
		"compute.instances.create",
		"compute.instances.list",
		"storage.buckets.create",
		"storage.buckets.list",
		"storage.objects.get",
	}
	assert.Equal(t, expected, perms)
}

func TestRoleExpanderUnknownRoleSkipped(t *testing.T) {
	re := &RoleExpander{
		rolePermissions: map[string][]string{
			"roles/viewer": {"storage.objects.get"},
		},
	}
	re.once.Do(func() {})

	perms, err := re.Expand(context.Background(), []string{"roles/viewer", "roles/nonexistent"})
	assert.NoError(t, err)
	assert.Equal(t, []string{"storage.objects.get"}, perms)
}

func TestRoleExpanderEmptyRoles(t *testing.T) {
	re := &RoleExpander{
		rolePermissions: map[string][]string{},
	}
	re.once.Do(func() {})

	perms, err := re.Expand(context.Background(), []string{})
	assert.NoError(t, err)
	assert.Empty(t, perms)
}
