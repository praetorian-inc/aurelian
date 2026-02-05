package recon

import (
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&ARGScan{})
}

// ARGScan scans Azure resources using ARG templates and enriches findings
type ARGScan struct{}

func (m *ARGScan) ID() string {
	return "arg-scan"
}

func (m *ARGScan) Name() string {
	return "Azure ARG Template Scanner with Enrichment"
}

func (m *ARGScan) Description() string {
	return "Scans Azure resources using ARG templates and enriches findings with security testing commands (only runs templates with arg-scan category)."
}

func (m *ARGScan) Platform() plugin.Platform {
	return plugin.PlatformAzure
}

func (m *ARGScan) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *ARGScan) OpsecLevel() string {
	return "moderate"
}

func (m *ARGScan) Authors() []string {
	return []string{"Praetorian"}
}

func (m *ARGScan) References() []string {
	return []string{}
}

func (m *ARGScan) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "subscription",
			Description: "Azure subscription ID (or 'all' to resolve to all subscriptions)",
			Type:        "string",
			Required:    true,
		},
		{
			Name:        "disable-enrichment",
			Description: "Disable enrichment of findings with security testing commands",
			Type:        "bool",
			Required:    false,
			Default:     false,
		},
		{
			Name:        "module-name",
			Description: "Name of the module for dynamic file naming",
			Type:        "string",
			Required:    false,
			Default:     "arg-scan",
		},
		{
			Name:        "category",
			Description: "Template category filter",
			Type:        "string",
			Required:    false,
			Default:     "arg-scan",
		},
	}
}

func (m *ARGScan) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Get parameters from config
	subscription, _ := cfg.Args["subscription"].(string)
	if subscription == "" {
		return nil, fmt.Errorf("subscription parameter is required")
	}

	disableEnrichment, _ := cfg.Args["disable-enrichment"].(bool)
	moduleName, _ := cfg.Args["module-name"].(string)
	if moduleName == "" {
		moduleName = "arg-scan"
	}

	category, _ := cfg.Args["category"].(string)
	if category == "" {
		category = "arg-scan"
	}

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
	// into direct function calls:
	//
	// 1. NewAzureSubscriptionGeneratorLink - Generate subscription IDs (resolve "all" to actual GUIDs)
	// 2. NewARGTemplateLoaderLink - Load ARG templates and create queries for each subscription
	// 3. NewARGTemplateQueryLink - Execute ARG queries and get resources
	// 4. NewARGEnrichmentLink - Enrich resources with security testing commands

	if cfg.Verbose {
		fmt.Fprintf(cfg.Output, "Scanning Azure subscription: %s\n", subscription)
		fmt.Fprintf(cfg.Output, "Module name: %s, Category: %s\n", moduleName, category)
		fmt.Fprintf(cfg.Output, "Enrichment: %v\n", !disableEnrichment)
	}

	return nil, fmt.Errorf("module implementation pending: arg-scan needs to be migrated from Janus chain/link architecture to direct function calls")
}
