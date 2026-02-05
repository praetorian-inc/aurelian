// pkg/plugin/link.go
package plugin

import (
	"context"
	"log/slog"
)

// Link represents a processing unit in a pipeline
// This replaces chain.Link
type Link interface {
	// Process handles a single input and may produce outputs
	Process(ctx context.Context, input any) ([]any, error)

	// Parameters returns the link's parameter definitions
	Parameters() []Parameter
}

// BaseLink provides common functionality for links
// This replaces chain.Base
type BaseLink struct {
	name    string
	args    map[string]any
	outputs []any
	logger  *slog.Logger
}

func NewBaseLink(name string, args map[string]any) *BaseLink {
	return &BaseLink{
		name:   name,
		args:   args,
		logger: slog.Default().With("link", name),
	}
}

// Arg retrieves a typed argument value
func (b *BaseLink) Arg(name string) any {
	return b.args[name]
}

// ArgString retrieves a string argument with default
func (b *BaseLink) ArgString(name string, defaultVal string) string {
	if v, ok := b.args[name].(string); ok {
		return v
	}
	return defaultVal
}

// ArgBool retrieves a bool argument with default
func (b *BaseLink) ArgBool(name string, defaultVal bool) bool {
	if v, ok := b.args[name].(bool); ok {
		return v
	}
	return defaultVal
}

// ArgInt retrieves an int argument with default
func (b *BaseLink) ArgInt(name string, defaultVal int) int {
	if v, ok := b.args[name].(int); ok {
		return v
	}
	return defaultVal
}

// ArgStringSlice retrieves a []string argument with default
func (b *BaseLink) ArgStringSlice(name string, defaultVal []string) []string {
	if v, ok := b.args[name].([]string); ok {
		return v
	}
	return defaultVal
}

// Send adds output to the collection (replaces l.Send())
func (b *BaseLink) Send(val any) {
	b.outputs = append(b.outputs, val)
}

// Outputs returns all collected outputs
func (b *BaseLink) Outputs() []any {
	return b.outputs
}

// ClearOutputs resets the output collection
func (b *BaseLink) ClearOutputs() {
	b.outputs = nil
}

// Logger returns the link's logger
func (b *BaseLink) Logger() *slog.Logger {
	return b.logger
}

// Name returns the link name
func (b *BaseLink) Name() string {
	return b.name
}
