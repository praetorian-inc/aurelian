package recon

import (
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&FindSecrets{})
}

// FindSecrets enumerates AWS resources and finds secrets using NoseyParker
type FindSecrets struct{}

func (m *FindSecrets) ID() string {
	return "find-secrets"
}

func (m *FindSecrets) Name() string {
	return "AWS Find Secrets"
}

func (m *FindSecrets) Description() string {
	return "Enumerate AWS resources and find secrets using NoseyParker"
}

func (m *FindSecrets) Platform() plugin.Platform {
	return plugin.PlatformAWS
}

func (m *FindSecrets) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *FindSecrets) OpsecLevel() string {
	return "moderate"
}

func (m *FindSecrets) Authors() []string {
	return []string{"Praetorian"}
}

func (m *FindSecrets) References() []string {
	return []string{}
}

func (m *FindSecrets) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "resource-type",
			Description: "AWS resource types to scan",
			Type:        "[]string",
			Required:    false,
			Default:     []string{"all"},
		},
		{
			Name:        "profile",
			Description: "AWS profile to use",
			Type:        "string",
			Required:    false,
		},
		{
			Name:        "max-events",
			Description: "Maximum number of log events to fetch per log group/stream (applies to CloudWatch Logs resources)",
			Type:        "int",
			Required:    false,
			Default:     10000,
		},
		{
			Name:        "max-streams",
			Description: "Maximum number of log streams to sample per log group (applies to CloudWatch Logs resources)",
			Type:        "int",
			Required:    false,
			Default:     10,
		},
		{
			Name:        "newest-first",
			Description: "Fetch newest events first instead of oldest (applies to CloudWatch Logs resources)",
			Type:        "bool",
			Required:    false,
			Default:     false,
		},
	}
}

func (m *FindSecrets) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Get parameters from config
	resourceType, _ := cfg.Args["resource-type"].([]string)
	if resourceType == nil {
		resourceType = []string{"all"}
	}

	profile, _ := cfg.Args["profile"].(string)
	maxEvents, _ := cfg.Args["max-events"].(int)
	if maxEvents == 0 {
		maxEvents = 10000
	}

	maxStreams, _ := cfg.Args["max-streams"].(int)
	if maxStreams == 0 {
		maxStreams = 10
	}

	newestFirst, _ := cfg.Args["newest-first"].(bool)

	// Check context cancellation
	if cfg.Context != nil {
		select {
		case <-cfg.Context.Done():
			return nil, cfg.Context.Err()
		default:
		}
	}

	// TODO: Implement the actual module logic
	// This is a placeholder that returns an error indicating the module needs implementation
	// The original Janus implementation used chains and links which need to be refactored
	// into direct function calls.

	if cfg.Verbose {
		fmt.Fprintf(cfg.Output, "Scanning AWS resources: %v\n", resourceType)
		if profile != "" {
			fmt.Fprintf(cfg.Output, "Using AWS profile: %s\n", profile)
		}
		fmt.Fprintf(cfg.Output, "Max events: %d, Max streams: %d, Newest first: %v\n", maxEvents, maxStreams, newestFirst)
	}

	return nil, fmt.Errorf("module implementation pending: find-secrets needs to be migrated from Janus chain/link architecture to direct function calls")
}
