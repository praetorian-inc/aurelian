package recon

import (
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&FindSecretsResource{})
}

// FindSecretsResource enumerates AWS resources and finds secrets using NoseyParker
type FindSecretsResource struct{}

// ID returns the unique identifier for this module
func (m *FindSecretsResource) ID() string {
	return "find-secrets-resource"
}

// Name returns the human-readable name
func (m *FindSecretsResource) Name() string {
	return "AWS Find Secrets Resource"
}

// Description returns a detailed description of what this module does
func (m *FindSecretsResource) Description() string {
	return "Enumerate AWS resources and find secrets using NoseyParker for a specific resource type"
}

// Platform returns the cloud platform this module targets
func (m *FindSecretsResource) Platform() plugin.Platform {
	return plugin.PlatformAWS
}

// Category returns the module category
func (m *FindSecretsResource) Category() plugin.Category {
	return plugin.CategoryRecon
}

// OpsecLevel returns the operational security level
func (m *FindSecretsResource) OpsecLevel() string {
	return "moderate"
}

// Authors returns the list of module authors
func (m *FindSecretsResource) Authors() []string {
	return []string{"Praetorian"}
}

// References returns any external references or documentation links
func (m *FindSecretsResource) References() []string {
	return []string{}
}

// Parameters defines the input parameters this module accepts
func (m *FindSecretsResource) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "resource-arn",
			Description: "AWS Resource ARN to scan for secrets",
			Type:        "string",
			Required:    true,
		},
		{
			Name:        "module-name",
			Description: "name of the module for dynamic file naming",
			Type:        "string",
			Required:    false,
			Default:     "find-secrets-resource",
		},
		{
			Name:        "continue-piping",
			Description: "whether to continue piping output to next stage",
			Type:        "bool",
			Required:    false,
			Default:     true,
		},
	}
}

// Run executes the module with the given configuration
func (m *FindSecretsResource) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Validate required parameters
	resourceArn, ok := cfg.Args["resource-arn"].(string)
	if !ok || resourceArn == "" {
		return nil, fmt.Errorf("resource-arn is required")
	}

	// Extract optional parameters
	moduleName := "find-secrets-resource"
	if name, ok := cfg.Args["module-name"].(string); ok && name != "" {
		moduleName = name
	}

	continuePiping := true
	if pipe, ok := cfg.Args["continue-piping"].(bool); ok {
		continuePiping = pipe
	}

	// TODO: Implement the actual secret finding logic
	// This will need to:
	// 1. Use general.SingleResourcePreprocessor to normalize input
	// 2. Call aws.FindSecrets to extract content from AWS resource
	// 3. Use aws.ResourceChainProcessor to handle resource chain processing
	// 4. Run noseyparker.Scanner to detect secrets
	// 5. Output results using runtime JSON outputter

	return []plugin.Result{
		{
			Data: map[string]any{
				"resource_arn":     resourceArn,
				"module_name":      moduleName,
				"continue_piping":  continuePiping,
				"status":           "not_implemented",
				"message":          "Module migrated to native plugin, implementation pending",
			},
			Metadata: map[string]any{
				"platform": string(m.Platform()),
				"category": string(m.Category()),
			},
		},
	}, nil
}
