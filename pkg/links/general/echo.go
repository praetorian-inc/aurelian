package general

import (
	"context"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

type Echo[T any] struct {
	*plugin.BaseLink
}

func NewEcho[T any](args map[string]any) *Echo[T] {
	return &Echo[T]{
		BaseLink: plugin.NewBaseLink("echo", args),
	}
}

func (e *Echo[T]) Process(ctx context.Context, input any) ([]any, error) {
	// Pass it through
	return []any{input}, nil
}

func (e *Echo[T]) Parameters() []plugin.Parameter {
	return nil
}
