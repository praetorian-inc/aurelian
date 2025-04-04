package aws

import (
	"slices"
	"testing"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/stretchr/testify/assert"
)

func TestNewAWSExpandActionsLink(t *testing.T) {

	t.Run("Expand Actions wildcard match", func(t *testing.T) {
		expected := []string{"lambda:InvokeFunction", "lambda:InvokeAsync", "lambda:InvokeFunctionUrl"}
		c := chain.NewChain(NewAWSExpandActionsLink())
		c.Send("lambda:i*")
		c.Close()

		expandedActions := []string{}
		for o, ok := chain.RecvAs[string](c); ok; o, ok = chain.RecvAs[string](c) {
			expandedActions = append(expandedActions, o)
		}
		slices.Sort(expandedActions)
		slices.Sort(expected)
		if !slices.Equal(expected, expandedActions) {
			t.Errorf("Expected %v, got %v", expected, expandedActions)
		}
	})

	t.Run("ExpandActions multiple wildcard and case insensitivity", func(t *testing.T) {
		expected := []string{"lambda:InvokeFunction", "lambda:InvokeAsync", "lambda:InvokeFunctionUrl"}
		c := chain.NewChain(NewAWSExpandActionsLink())
		c.Send("lambda:i*voKe*")
		c.Close()

		expandedActions := []string{}
		for o, ok := chain.RecvAs[string](c); ok; o, ok = chain.RecvAs[string](c) {
			expandedActions = append(expandedActions, o)
		}
		slices.Sort(expandedActions)
		slices.Sort(expected)
		if !slices.Equal(expected, expandedActions) {
			t.Errorf("Expected %v, got %v", expected, expandedActions)
		}
	})

	t.Run("ExpandActions wildcard", func(t *testing.T) {
		c := chain.NewChain(NewAWSExpandActionsLink())
		c.Send("*")
		c.Close()

		expandedActions := []string{}
		for o, ok := chain.RecvAs[string](c); ok; o, ok = chain.RecvAs[string](c) {
			expandedActions = append(expandedActions, o)
		}
		assert.Greater(t, len(expandedActions), 10000)
	})
}
