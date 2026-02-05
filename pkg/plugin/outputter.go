package plugin

import "fmt"

// Outputter is the native interface for output handling.
// This replaces chain.Outputter from janus-framework.
type Outputter interface {
	// Initialize prepares the outputter with configuration (called before first output)
	Initialize(cfg Config) error

	// Output writes a single result
	Output(result any) error

	// Complete finalizes output (called after all outputs)
	Complete() error
}

// OutputterFunc adapts a function to the Outputter interface
type OutputterFunc func(any) error

func (f OutputterFunc) Initialize(cfg Config) error { return nil }
func (f OutputterFunc) Output(v any) error          { return f(v) }
func (f OutputterFunc) Complete() error              { return nil }

// GetArg retrieves a typed argument from Config.Args
// This replaces cfg.As[T]() from janus-framework
func GetArg[T any](cfg Config, name string) (T, error) {
	var zero T
	value, ok := cfg.Args[name]
	if !ok {
		return zero, fmt.Errorf("argument %q not found", name)
	}
	typed, ok := value.(T)
	if !ok {
		return zero, fmt.Errorf("argument %q has type %T, expected %T", name, value, zero)
	}
	return typed, nil
}

// GetArgOrDefault retrieves a typed argument from Config.Args or returns a default
func GetArgOrDefault[T any](cfg Config, name string, defaultValue T) T {
	value, err := GetArg[T](cfg, name)
	if err != nil {
		return defaultValue
	}
	return value
}
