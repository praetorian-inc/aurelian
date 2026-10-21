package dnstakeover

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"
)

// NewChecker must carry the scan's resolved project list into the Checker:
// Cloud DNS zone ownership cannot be established without it.
func TestNewChecker_CarriesResolvedProjects(t *testing.T) {
	projects := []string{"hub-dns-project", "child-app-project"}

	c, err := NewChecker([]option.ClientOption{option.WithoutAuthentication()}, projects)
	require.NoError(t, err)

	assert.Equal(t, projects, c.projectIDs)
}

// The caller's slice must not alias the Checker's, so a later mutation by the
// caller cannot change which projects the ownership lookup consults.
func TestNewChecker_DoesNotAliasCallerSlice(t *testing.T) {
	projects := []string{"hub-dns-project"}

	c, err := NewChecker([]option.ClientOption{option.WithoutAuthentication()}, projects)
	require.NoError(t, err)

	projects[0] = "mutated"
	assert.Equal(t, []string{"hub-dns-project"}, c.projectIDs)
}
