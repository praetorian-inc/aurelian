package recon

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/links/gcp/common"
	"github.com/praetorian-inc/aurelian/pkg/links/gcp/hierarchy"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&GcpSummary{})
}

// GcpSummary summarizes resources within an organization, folder, or project scope
type GcpSummary struct{}

// Metadata methods
func (m *GcpSummary) ID() string {
	return "summary"
}

func (m *GcpSummary) Name() string {
	return "GCP Summary"
}

func (m *GcpSummary) Description() string {
	return `Summarize resources within an organization, folder, or project scope (requires Asset API).

This module provides a comprehensive summary of GCP resources within a specified scope:

**Supported Scopes:**
- **Organization**: Summarize all resources across an entire GCP organization
- **Folder**: Summarize resources within a specific folder
- **Project**: Summarize resources within a single project

**Requirements:**
- Asset API must be enabled in the target scope
- Appropriate IAM permissions to access Asset API (cloudasset.assets.searchAllResources)

**Detection Method:**
1. Determines the scope (organization, folder, or project) from parameters
2. Retrieves scope information using Cloud Resource Manager API
3. Uses Cloud Asset API to search and enumerate all resources within the scope
4. Aggregates and formats the resource inventory

The module provides detailed resource listings including resource types, locations, and metadata.`
}

func (m *GcpSummary) Platform() plugin.Platform {
	return plugin.PlatformGCP
}

func (m *GcpSummary) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *GcpSummary) OpsecLevel() string {
	return "moderate"
}

func (m *GcpSummary) Authors() []string {
	return []string{"Praetorian"}
}

func (m *GcpSummary) References() []string {
	return []string{
		"https://cloud.google.com/asset-inventory/docs/overview",
		"https://cloud.google.com/asset-inventory/docs/search-resources",
	}
}

func (m *GcpSummary) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "project",
			Description: "GCP project name or ID",
			Type:        "string",
			Required:    false,
		},
		{
			Name:        "org",
			Description: "GCP organization name or ID",
			Type:        "string",
			Required:    false,
		},
		{
			Name:        "folder",
			Description: "GCP folder name or ID",
			Type:        "string",
			Required:    false,
		},
		{
			Name:        "asset-api-project",
			Description: "GCP project to use for Asset API calls (defaults to scope project)",
			Type:        "string",
			Required:    false,
		},
	}
}

// Run executes the GCP summary module
func (m *GcpSummary) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Initialize context if not provided
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	// Parse scope from parameters
	scope, err := common.ParseScopeArgs(cfg.Args)
	if err != nil {
		return nil, fmt.Errorf("failed to parse scope parameters: %w", err)
	}

	slog.Info("Running GCP summary", "scope_type", scope.Type, "scope_value", scope.Value)

	// Phase 1: Get scope resource info
	infoLink, assetSearchLink := m.buildLinksForScope(scope.Type, cfg.Args)
	if infoLink == nil || assetSearchLink == nil {
		return nil, fmt.Errorf("invalid scope type: %s", scope.Type)
	}

	scopeResults, err := infoLink.Process(ctx, scope.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to get %s info: %w", scope.Type, err)
	}

	if len(scopeResults) == 0 {
		return nil, fmt.Errorf("%s not found: %s", scope.Type, scope.Value)
	}

	scopeResource, ok := scopeResults[0].(output.CloudResource)
	if !ok {
		return nil, fmt.Errorf("unexpected scope result type: %T", scopeResults[0])
	}

	slog.Info("Processing scope", "type", scope.Type, "id", scopeResource.ResourceID, "name", scopeResource.DisplayName)

	// Phase 2: Search assets in scope
	assetResults, err := assetSearchLink.Process(ctx, scopeResource)
	if err != nil {
		return nil, fmt.Errorf("failed to search assets: %w", err)
	}

	slog.Info("Asset search complete", "results_count", len(assetResults))

	// Build results
	results := make([]plugin.Result, 0, len(assetResults))
	for _, assetResult := range assetResults {
		results = append(results, plugin.Result{
			Data: assetResult,
			Metadata: map[string]any{
				"module":      "summary",
				"platform":    "gcp",
				"category":    "recon",
				"opsec_level": "moderate",
				"scope_type":  scope.Type,
				"scope_id":    scopeResource.ResourceID,
			},
		})
	}

	return results, nil
}

// hierarchyLink is a local interface for hierarchy links
type hierarchyLink interface {
	Process(ctx context.Context, input any) ([]any, error)
}

// buildLinksForScope creates appropriate links based on scope type
func (m *GcpSummary) buildLinksForScope(scopeType string, args map[string]any) (infoLink, assetSearchLink hierarchyLink) {
	switch scopeType {
	case "org":
		return hierarchy.NewGcpOrgInfoLink(args), hierarchy.NewGcpAssetSearchOrgLink(args)
	case "folder":
		return hierarchy.NewGcpFolderInfoLink(args), hierarchy.NewGcpAssetSearchFolderLink(args)
	case "project":
		return hierarchy.NewGcpProjectInfoLink(args), hierarchy.NewGcpAssetSearchProjectLink(args)
	default:
		return nil, nil
	}
}
