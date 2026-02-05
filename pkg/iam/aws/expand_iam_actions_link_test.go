package aws

import (
	"context"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewAWSExpandActionsLink(t *testing.T) {

	t.Run("Expand Actions wildcard match", func(t *testing.T) {
		expected := []string{"lambda:InvokeFunction", "lambda:InvokeAsync", "lambda:InvokeFunctionUrl"}

		link := NewAWSExpandActionsLink(map[string]any{})
		if err := link.Initialize(); err != nil {
			t.Fatalf("Failed to initialize link: %v", err)
		}

		outputs, err := link.Process(context.Background(), "lambda:i*")
		if err != nil {
			t.Fatalf("Process failed: %v", err)
		}

		expandedActions := []string{}
		for _, output := range outputs {
			if action, ok := output.(string); ok {
				expandedActions = append(expandedActions, action)
			}
		}

		slices.Sort(expandedActions)
		slices.Sort(expected)
		if !slices.Equal(expected, expandedActions) {
			t.Errorf("Expected %v, got %v", expected, expandedActions)
		}
	})

	t.Run("ExpandActions multiple wildcard and case insensitivity", func(t *testing.T) {
		expected := []string{"lambda:InvokeFunction", "lambda:InvokeAsync", "lambda:InvokeFunctionUrl"}

		link := NewAWSExpandActionsLink(map[string]any{})
		if err := link.Initialize(); err != nil {
			t.Fatalf("Failed to initialize link: %v", err)
		}

		outputs, err := link.Process(context.Background(), "lambda:i*voKe*")
		if err != nil {
			t.Fatalf("Process failed: %v", err)
		}

		expandedActions := []string{}
		for _, output := range outputs {
			if action, ok := output.(string); ok {
				expandedActions = append(expandedActions, action)
			}
		}

		slices.Sort(expandedActions)
		slices.Sort(expected)
		if !slices.Equal(expected, expandedActions) {
			t.Errorf("Expected %v, got %v", expected, expandedActions)
		}
	})

	t.Run("ExpandActions wildcard", func(t *testing.T) {
		link := NewAWSExpandActionsLink(map[string]any{})
		if err := link.Initialize(); err != nil {
			t.Fatalf("Failed to initialize link: %v", err)
		}

		outputs, err := link.Process(context.Background(), "*")
		if err != nil {
			t.Fatalf("Process failed: %v", err)
		}

		expandedActions := []string{}
		for _, output := range outputs {
			if action, ok := output.(string); ok {
				expandedActions = append(expandedActions, action)
			}
		}

		assert.Greater(t, len(expandedActions), 10000)
	})
}
