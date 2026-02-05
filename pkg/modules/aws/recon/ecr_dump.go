package recon

import (
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&ECRDump{})
}

// ECRDump implements the plugin.Module interface for ECR container filesystem dumping
type ECRDump struct{}

func (m *ECRDump) ID() string {
	return "ecr-dump"
}

func (m *ECRDump) Name() string {
	return "ECR Dump"
}

func (m *ECRDump) Description() string {
	return "Dump ECR container filesystems to disk and optionally scan for secrets using NoseyParker."
}

func (m *ECRDump) Platform() plugin.Platform {
	return plugin.PlatformAWS
}

func (m *ECRDump) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *ECRDump) OpsecLevel() string {
	return "moderate"
}

func (m *ECRDump) Authors() []string {
	return []string{"Praetorian"}
}

func (m *ECRDump) References() []string {
	return []string{}
}

func (m *ECRDump) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "resource-type",
			Description: "AWS resource types to scan",
			Type:        "[]string",
			Default:     []string{"AWS::ECR::Repository", "AWS::ECR::PublicRepository"},
		},
		{
			Name:        "extract",
			Description: "Extract container filesystems to disk",
			Type:        "bool",
			Default:     true,
		},
		{
			Name:        "noseyparker-scan",
			Description: "Scan extracted filesystems with NoseyParker for secrets",
			Type:        "bool",
			Default:     true,
		},
		{
			Name:        "module-name",
			Description: "Name of the module for dynamic file naming",
			Type:        "string",
			Default:     "ecr-dump",
		},
		{
			Name:        "profile",
			Description: "AWS profile name",
			Type:        "string",
		},
		{
			Name:        "profile-dir",
			Description: "AWS profile directory",
			Type:        "string",
		},
	}
}

func (m *ECRDump) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// TODO: Implement ECR dump functionality
	// This requires:
	// 1. CloudControl integration to list ECR repositories
	// 2. ECR API calls to list images
	// 3. Docker operations to pull, save, and extract images
	// 4. NoseyParker integration for secret scanning
	//
	// The original implementation used Janus framework chains which provided
	// automatic data flow between links. The native plugin architecture requires
	// explicit orchestration of these steps.
	//
	// This migration is blocked because:
	// - The module dependencies (cloudcontrol, ecr, docker, noseyparker packages)
	//   are tightly coupled to Janus framework's chain.Link interface
	// - A full migration requires either:
	//   a) Porting all dependencies to plugin.Processor interface
	//   b) Creating adapters between Janus links and plugin processors
	//   c) Reimplementing the functionality directly in this Run method
	//
	// Recommended approach: Mark this module for future migration after
	// establishing adapter patterns for Janus link conversion

	return nil, fmt.Errorf("ECR dump module migration incomplete: requires Janus link adapter pattern")
}

// AWSECRResourceTypes implements the SupportsResourceTypes interface
type AWSECRResourceTypes struct{}

func (a *AWSECRResourceTypes) SupportedResourceTypes() []string {
	return []string{
		"AWS::ECR::Repository",
		"AWS::ECR::PublicRepository",
	}
}
