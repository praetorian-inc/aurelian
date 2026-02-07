package recon

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/links/aws"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/cloudcontrol"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/ssm"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
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
			Name:        "profile-dir",
			Description: "AWS profile directory",
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
		{
			Name:        "verify",
			Description: "Validate detected secrets against their source APIs",
			Type:        "bool",
			Required:    false,
			Default:     false,
		},
		{
			Name:        "datastore",
			Description: "Path to Titus SQLite database",
			Type:        "string",
			Required:    false,
			Default:     "aurelian-output/titus.db",
		},
	}
}

func (m *FindSecrets) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Get context
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	// Get parameters from config
	resourceType, _ := cfg.Args["resource-type"].([]string)
	if resourceType == nil {
		resourceType = []string{"all"}
	}

	profile, _ := cfg.Args["profile"].(string)
	profileDir, _ := cfg.Args["profile-dir"].(string)
	maxEvents, _ := cfg.Args["max-events"].(int)
	if maxEvents == 0 {
		maxEvents = 10000
	}

	maxStreams, _ := cfg.Args["max-streams"].(int)
	if maxStreams == 0 {
		maxStreams = 10
	}

	newestFirst, _ := cfg.Args["newest-first"].(bool)

	verify, _ := cfg.Args["verify"].(bool)
	datastore, _ := cfg.Args["datastore"].(string)
	if datastore == "" {
		datastore = "aurelian-output/titus.db"
	}

	// Check context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Build args map for links
	args := map[string]any{
		"profile":       profile,
		"profile-dir":   profileDir,
		"max-events":    maxEvents,
		"max-streams":   maxStreams,
		"newest-first":  newestFirst,
		"verify":        verify,
		"datastore":     datastore,
	}

	// Parse regions
	regions, err := helpers.ParseRegionsOption("all", profile, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse regions: %w", err)
	}
	args["regions"] = regions

	// Initialize FindSecrets processor
	fsLink := aws.NewAWSFindSecrets(args)

	// Resolve "all" to actual resource types
	if len(resourceType) == 1 && resourceType[0] == "all" {
		resourceType = fsLink.SupportedResourceTypes()
	}

	if cfg.Verbose {
		fmt.Fprintf(cfg.Output, "Scanning AWS resources: %v\n", resourceType)
		if profile != "" {
			fmt.Fprintf(cfg.Output, "Using AWS profile: %s\n", profile)
		}
		fmt.Fprintf(cfg.Output, "Regions: %v\n", regions)
		fmt.Fprintf(cfg.Output, "Max events: %d, Max streams: %d, Newest first: %v\n", maxEvents, maxStreams, newestFirst)
	}

	var allResults []plugin.Result

	// Initialize CloudControl enumerator
	ccLink := cloudcontrol.NewAWSCloudControl(args)

	// For each resource type, enumerate and process
	for _, resType := range resourceType {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return allResults, ctx.Err()
		default:
		}

		if cfg.Verbose {
			fmt.Fprintf(cfg.Output, "Processing resource type: %s\n", resType)
		}

		var resources []any

		// Use SSM-specific lister for documents (with Owner=Self filter)
		if resType == "AWS::SSM::Document" {
			// Use SSM native lister with Owner=Self filter
			ssmDocLister := ssm.NewAWSListSSMDocuments(args)

			// For each region, list documents
			for _, region := range regions {
				placeholder := &types.EnrichedResourceDescription{
					TypeName: resType,
					Region:   region,
				}

				regionDocs, err := ssmDocLister.Process(ctx, placeholder)
				if err != nil {
					slog.Warn("Failed to list SSM documents", "region", region, "error", err)
					if cfg.Verbose {
						fmt.Fprintf(cfg.Output, "Warning: failed to list SSM documents in %s: %v\n", region, err)
					}
					continue
				}

				resources = append(resources, regionDocs...)
			}
		} else {
			// Enumerate resources via CloudControl
			_, err := ccLink.Process(ctx, resType)
			if err != nil {
				slog.Warn("Failed to enumerate resources", "type", resType, "error", err)
				if cfg.Verbose {
					fmt.Fprintf(cfg.Output, "Warning: failed to enumerate %s: %v\n", resType, err)
				}
				continue
			}

			// Get enumerated resources from CloudControl outputs
			resources = ccLink.Outputs()
			ccLink.ClearOutputs()
		}

		// Process each resource through FindSecrets
		for _, resource := range resources {
			erd, ok := resource.(*types.EnrichedResourceDescription)
			if !ok {
				continue
			}

			if cfg.Verbose {
				fmt.Fprintf(cfg.Output, "  Processing: %s (region: %s)\n", erd.Identifier, erd.Region)
			}

			outputs, err := fsLink.Process(ctx, erd)
			if err != nil {
				slog.Warn("Failed to process resource", "id", erd.Identifier, "error", err)
				if cfg.Verbose {
					fmt.Fprintf(cfg.Output, "Warning: failed to process resource %s: %v\n", erd.Identifier, err)
				}
				continue
			}

			// Convert outputs to Results
			for _, output := range outputs {
				allResults = append(allResults, plugin.Result{
					Data: output,
					Metadata: map[string]any{
						"resource_type": resType,
						"resource_id":   erd.Identifier,
						"region":        erd.Region,
						"module":        "find-secrets",
						"platform":      "aws",
					},
				})
			}
		}

		if cfg.Verbose {
			fmt.Fprintf(cfg.Output, "Completed processing resource type: %s (%d resources found)\n", resType, len(resources))
		}
	}

	if cfg.Verbose {
		fmt.Fprintf(cfg.Output, "Scan complete. Total results: %d\n", len(allResults))
	}

	return allResults, nil
}
