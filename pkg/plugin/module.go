// Package plugin provides the core plugin architecture for Aurelian modules.
// This replaces the dependency on the Janus framework with a simple, standalone
// plugin system inspired by Nerva's architecture.
package plugin

import (
	"context"
	"io"
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

// Result is the standardized output type for all modules
type Result struct {
	Data     any            // The actual result data
	Metadata map[string]any // Additional metadata
	Error    error          // Any error that occurred
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

	// Parameters
	Parameters() []Parameter

	// Execution
	Run(cfg Config) ([]Result, error)
}
