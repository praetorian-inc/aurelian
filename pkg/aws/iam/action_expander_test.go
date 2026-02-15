package iam

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActionExpander_Expand(t *testing.T) {
	expander := &ActionExpander{}

	t.Run("Expand Actions wildcard match", func(t *testing.T) {
		expected := []string{"lambda:InvokeFunction", "lambda:InvokeAsync", "lambda:InvokeFunctionUrl"}
		
		results, err := expander.Expand("lambda:i*")
		require.NoError(t, err)
		
		slices.Sort(results)
		slices.Sort(expected)
		assert.Equal(t, expected, results)
	})

	t.Run("ExpandActions multiple wildcard and case insensitivity", func(t *testing.T) {
		expected := []string{"lambda:InvokeFunction", "lambda:InvokeAsync", "lambda:InvokeFunctionUrl"}
		
		results, err := expander.Expand("lambda:i*voKe*")
		require.NoError(t, err)
		
		slices.Sort(results)
		slices.Sort(expected)
		assert.Equal(t, expected, results)
	})

	t.Run("ExpandActions wildcard", func(t *testing.T) {
		results, err := expander.Expand("*")
		require.NoError(t, err)
		
		assert.Greater(t, len(results), 10000)
	})
}
