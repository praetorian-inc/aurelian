// Package plugin provides the core plugin architecture for Aurelian modules.
// This replaces the dependency on the Janus framework with a simple, standalone
// plugin system inspired by Nerva's architecture.
package plugin

import (
	"context"
	"fmt"
	"io"
	"reflect"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// Platform represents the cloud platform or service category
type Platform string

const (
	PlatformAWS   Platform = "aws"
	PlatformAzure Platform = "azure"
	PlatformGCP   Platform = "gcp"
	PlatformSaaS  Platform = "saas"
	PlatformM365  Platform = "m365"
)

// Category represents the module category
type Category string

const (
	CategoryRecon   Category = "recon"
	CategoryAnalyze Category = "analyze"
	CategorySecrets Category = "secrets"
)

const (
	AnyResourceType = "any"
)

// Config holds runtime configuration for a module
type Config struct {
	Args    map[string]any  // Runtime arguments (backward compat)
	Params  Parameters      // Typed parameter set
	Context context.Context // Execution context
	Output  io.Writer       // Output destination
	Verbose bool            // Verbose logging
	Log     *Logger         // User-facing terminal logger
}

// Info logs an informational message if a Logger is configured.
func (c Config) Info(format string, args ...any) {
	if c.Log != nil {
		c.Log.Info(format, args...)
	}
}

// Success logs a success message if a Logger is configured.
func (c Config) Success(format string, args ...any) {
	if c.Log != nil {
		c.Log.Success(format, args...)
	}
}

// Warn logs a warning message if a Logger is configured.
func (c Config) Warn(format string, args ...any) {
	if c.Log != nil {
		c.Log.Warn(format, args...)
	}
}

// Fail logs a failure message if a Logger is configured.
func (c Config) Fail(format string, args ...any) {
	if c.Log != nil {
		c.Log.Fail(format, args...)
	}
}

// Module is the core interface that all Aurelian modules implement
type Module interface {
	// Metadata
	ID() string
	Name() string
	Description() string
	Platform() Platform
	Category() Category
	OpsecLevel() string
	Authors() []string
	References() []string
	SupportedResourceTypes() []string

	// Parameters returns a pointer to the module's config struct for parameter
	// binding, or nil if the module has no parameters. The returned value is
	// used both for deriving CLI flags (via ParametersFrom) and as the bind
	// target for Bind before Run is called.
	Parameters() any

	// Execution — send results into the pipeline via out.Send().
	// The caller owns the pipeline lifecycle (including Close).
	Run(cfg Config, out *pipeline.P[model.AurelianModel]) error
}

// ModuleWrapper wraps a Module so that Run automatically binds cfg.Args into
// the module's Parameters struct before delegating to the inner Run method.
// All modules retrieved from the registry are wrapped, ensuring callers never
// need to call Bind manually.
type PostBinder interface {
	PostBind(cfg Config, m Module) error
}

type ModuleWrapper struct {
	Module
}

func (m *ModuleWrapper) Run(cfg Config, out *pipeline.P[model.AurelianModel]) error {
	if cfg.Log == nil {
		cfg.Log = DiscardLogger()
	}
	if target := m.Parameters(); target != nil {
		if err := Bind(cfg, target); err != nil {
			return fmt.Errorf("parameter validation failed: %w", err)
		}
		if err := runPostBinders(cfg, m.Module, target); err != nil {
			return fmt.Errorf("parameter post-bind failed: %w", err)
		}
	}
	return m.Module.Run(cfg, out)
}

func runPostBinders(cfg Config, mod Module, target any) error {
	v := reflect.ValueOf(target)
	if !v.IsValid() {
		return nil
	}
	return runPostBindersValue(cfg, mod, v)
}

func runPostBindersValue(cfg Config, mod Module, v reflect.Value) error {
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil
	}

	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		fieldType := t.Field(i)
		if !fieldType.Anonymous {
			continue
		}
		fieldValue := v.Field(i)
		if err := runPostBindersValue(cfg, mod, fieldValue); err != nil {
			return err
		}
	}

	if !v.CanAddr() {
		return nil
	}
	if pb, ok := v.Addr().Interface().(PostBinder); ok {
		return pb.PostBind(cfg, mod)
	}

	return nil
}
