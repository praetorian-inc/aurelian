package iam

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAllPrivescPermissions_NonEmpty(t *testing.T) {
	perms := AllPrivescPermissions()
	assert.NotEmpty(t, perms)
}

func TestAllPrivescPermissions_Deduplicated(t *testing.T) {
	perms := AllPrivescPermissions()
	seen := make(map[string]struct{})
	for _, p := range perms {
		_, dup := seen[p]
		assert.False(t, dup, "duplicate permission: %s", p)
		seen[p] = struct{}{}
	}
}

func TestMatchPaths_AllPermissions(t *testing.T) {
	all := AllPrivescPermissions()
	matched := MatchPaths(all)
	assert.Len(t, matched, len(PrivescPaths))
}

func TestMatchPaths_EmptyPermissions(t *testing.T) {
	matched := MatchPaths(nil)
	assert.Empty(t, matched)

	matched = MatchPaths([]string{})
	assert.Empty(t, matched)
}

func TestMatchPaths_PartialPermissions(t *testing.T) {
	// Only grant iam.serviceAccountKeys.create - should match exactly one path.
	matched := MatchPaths([]string{"iam.serviceAccountKeys.create"})
	require.Len(t, matched, 1)
	assert.Equal(t, "gcp-privesc-sa-key-create", matched[0].Name)
}

func TestMatchPaths_MultiPermissionPath(t *testing.T) {
	// Grant only one of two required permissions - should not match.
	matched := MatchPaths([]string{"iam.serviceAccounts.actAs"})
	for _, m := range matched {
		// None of the matched paths should require additional permissions
		// beyond iam.serviceAccounts.actAs.
		assert.Len(t, m.Permissions, 1, "path %s should not match with only actAs", m.Name)
	}

	// Grant both permissions for Cloud Functions path.
	matched = MatchPaths([]string{"iam.serviceAccounts.actAs", "cloudfunctions.functions.create"})
	var names []string
	for _, m := range matched {
		names = append(names, m.Name)
	}
	assert.Contains(t, names, "gcp-privesc-cloudfunctions")
}

func TestPrivescPaths_RequiredFields(t *testing.T) {
	for _, p := range PrivescPaths {
		t.Run(p.Name, func(t *testing.T) {
			assert.NotEmpty(t, p.Name, "path must have a name")
			assert.NotEmpty(t, p.Description, "path must have a description")
			assert.NotEmpty(t, p.Permissions, "path must have at least one permission")
			assert.NotEqual(t, output.RiskSeverity(""), p.Severity, "path must have a severity")
		})
	}
}
