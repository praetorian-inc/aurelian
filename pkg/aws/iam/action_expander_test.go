package iam

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The expander reads live AWS action data, so AWS can add matching actions at
// any time. Assert that known actions are present, that every result really
// matches the pattern, and that a known non-match is excluded — never pin the
// exact list.
func assertExpansion(t *testing.T, results []string, matches *regexp.Regexp, known []string, absent string) {
	t.Helper()
	assert.Subset(t, results, known)
	assert.NotContains(t, results, absent)
	for _, r := range results {
		assert.True(t, strings.HasPrefix(r, "lambda:"), "result %q lacks lambda: prefix", r)
		assert.Regexp(t, matches, r)
	}
}

func TestActionExpander_Expand(t *testing.T) {
	expander := &ActionExpander{}
	known := []string{"lambda:InvokeFunction", "lambda:InvokeAsync", "lambda:InvokeFunctionUrl"}

	t.Run("Expand Actions wildcard match", func(t *testing.T) {
		results, err := expander.Expand("lambda:i*")
		require.NoError(t, err)
		assertExpansion(t, results, regexp.MustCompile(`^(?i)lambda:i`), known, "lambda:GetFunction")
	})

	t.Run("ExpandActions multiple wildcard and case insensitivity", func(t *testing.T) {
		results, err := expander.Expand("lambda:i*voKe*")
		require.NoError(t, err)
		assertExpansion(t, results, regexp.MustCompile(`^(?i)lambda:i.*voke`), known, "lambda:GetFunction")
	})

	t.Run("ExpandActions wildcard", func(t *testing.T) {
		results, err := expander.Expand("*")
		require.NoError(t, err)
		assert.Greater(t, len(results), 10000)
	})
}
