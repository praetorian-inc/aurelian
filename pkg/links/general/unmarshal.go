package general

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// TypedUnmarshalLink unmarshals JSON strings into a specific type.
type TypedUnmarshalLink[T any] struct {
	*plugin.BaseLink
}

// NewTypedUnmarshalOutputLink creates a link that unmarshals JSON strings into a specific type.
// This provides more flexibility when you know the exact type you want to unmarshal into.
func NewTypedUnmarshalOutputLink[T any](args map[string]any) *TypedUnmarshalLink[T] {
	return &TypedUnmarshalLink[T]{
		BaseLink: plugin.NewBaseLink("unmarshal", args),
	}
}

func (l *TypedUnmarshalLink[T]) Process(ctx context.Context, input any) ([]any, error) {
	inputStr, ok := input.(string)
	if !ok {
		return nil, fmt.Errorf("expected string input, got %T", input)
	}

	var result T
	err := json.Unmarshal([]byte(inputStr), &result)
	if err != nil {
		slog.Error("Failed to unmarshal JSON", "error", err, "input", inputStr)
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return []any{result}, nil
}

func (l *TypedUnmarshalLink[T]) Parameters() []plugin.Parameter {
	return nil
}
