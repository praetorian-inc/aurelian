package iam

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActionExpander_Expand(t *testing.T) {
	expander := &ActionExpander{}

	t.Run("Expand Actions wildcard match", func(t *testing.T) {
		knownActions := []string{"lambda:InvokeFunction", "lambda:InvokeAsync", "lambda:InvokeFunctionUrl"}

		results, err := expander.Expand("lambda:i*")
		require.NoError(t, err)

		assert.Subset(t, results, knownActions, "expected known lambda:Invoke* actions to be present")
		for _, r := range results {
			assert.True(t, strings.HasPrefix(strings.ToLower(r), "lambda:i"),
				"result %q should match lambda:i* pattern", r)
		}
	})

	t.Run("ExpandActions multiple wildcard and case insensitivity", func(t *testing.T) {
		knownActions := []string{"lambda:InvokeFunction", "lambda:InvokeAsync", "lambda:InvokeFunctionUrl"}

		results, err := expander.Expand("lambda:i*voKe*")
		require.NoError(t, err)

		assert.Subset(t, results, knownActions, "expected known lambda:Invoke* actions to be present")
		for _, r := range results {
			lower := strings.ToLower(r)
			assert.True(t, strings.HasPrefix(lower, "lambda:i") && strings.Contains(lower, "voke"),
				"result %q should match lambda:i*voKe* pattern", r)
		}
	})

	t.Run("ExpandActions wildcard", func(t *testing.T) {
		results, err := expander.Expand("*")
		require.NoError(t, err)

		assert.Greater(t, len(results), 10000)
	})

	t.Run("Expand no wildcard passthrough", func(t *testing.T) {
		results, err := expander.Expand("s3:GetObject")
		require.NoError(t, err)

		assert.Equal(t, []string{"s3:GetObject"}, results)
	})
}
