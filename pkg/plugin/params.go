// Package plugin provides the core plugin architecture for Aurelian modules.
package plugin

// ParamOption allows building parameters fluently
type ParamOption func(*Parameter)

// NewParam creates a new parameter (mirrors cfg.NewParam API)
// This replaces github.com/praetorian-inc/janus-framework/pkg/chain/cfg.NewParam
func NewParam[T any](name, description string, opts ...ParamOption) Parameter {
	p := Parameter{
		Name:        name,
		Description: description,
		Type:        detectType[T](),
	}
	for _, opt := range opts {
		opt(&p)
	}
	return p
}

// WithDefault sets a default value for the parameter
func WithDefault[T any](val T) ParamOption {
	return func(p *Parameter) {
		p.Default = val
	}
}

// WithRequired marks the parameter as required
func WithRequired() ParamOption {
	return func(p *Parameter) {
		p.Required = true
	}
}

// WithShortcode sets the shortcode (single char flag)
func WithShortcode(s string) ParamOption {
	return func(p *Parameter) {
		p.Shortcode = s
	}
}

// WithHidden hides the parameter from help output
func WithHidden() ParamOption {
	return func(p *Parameter) {
		p.Hidden = true
	}
}

func detectType[T any]() string {
	var zero T
	switch any(zero).(type) {
	case string:
		return "string"
	case int:
		return "int"
	case int64:
		return "int64"
	case bool:
		return "bool"
	case []string:
		return "[]string"
	case float64:
		return "float64"
	default:
		return "any"
	}
}
