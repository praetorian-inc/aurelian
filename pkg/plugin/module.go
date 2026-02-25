// Package plugin provides the core plugin architecture for Aurelian modules.
// This replaces the dependency on the Janus framework with a simple, standalone
// plugin system inspired by Nerva's architecture.
package plugin

import (
	"context"
	"fmt"
	"io"

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
type ModuleWrapper struct {
	Module
}

func (m *ModuleWrapper) Run(cfg Config, out *pipeline.P[model.AurelianModel]) error {
	if target := m.Parameters(); target != nil {
		if err := Bind(cfg, target); err != nil {
			return fmt.Errorf("parameter validation failed: %w", err)
		}
	}
	return m.Module.Run(cfg, out)
}
