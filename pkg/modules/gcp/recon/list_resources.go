package recon

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/links/gcp/applications"
	"github.com/praetorian-inc/aurelian/pkg/links/gcp/common"
	"github.com/praetorian-inc/aurelian/pkg/links/gcp/compute"
	"github.com/praetorian-inc/aurelian/pkg/links/gcp/containers"
	"github.com/praetorian-inc/aurelian/pkg/links/gcp/hierarchy"
	"github.com/praetorian-inc/aurelian/pkg/links/gcp/storage"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
)

func init() {
	plugin.Register(&GcpListResources{})
}

// GcpListResources lists GCP resources across organization, folder, or project scope
type GcpListResources struct{}

// Metadata methods
func (m *GcpListResources) ID() string {
	return "list-resources"
}

func (m *GcpListResources) Name() string {
	return "GCP List Resources"
}

func (m *GcpListResources) Description() string {
	return "List GCP resources across organization, folder, or project scope with optional resource type filtering."
}

func (m *GcpListResources) Platform() plugin.Platform {
	return plugin.PlatformGCP
}

func (m *GcpListResources) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *GcpListResources) OpsecLevel() string {
	return "moderate"
}

func (m *GcpListResources) Authors() []string {
	return []string{"Praetorian"}
}

func (m *GcpListResources) References() []string {
	return []string{}
}

func (m *GcpListResources) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "project",
			Description: "GCP project ID",
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
			Description: "GCP folder ID",
			Type:        "string",
			Required:    false,
		},
		{
			Name:        "type",
			Description: "Resource types to list (comma-separated or 'all')",
			Type:        "[]string",
			Required:    false,
			Default:     []string{"all"},
		},
		{
			Name:        "include-sys-projects",
			Description: "Include system projects in results",
			Type:        "bool",
			Required:    false,
			Default:     true,
		},
	}
}

// Run executes the list resources module
func (m *GcpListResources) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Parse scope configuration
	scope, err := m.parseScopeArgs(cfg.Args)
	if err != nil {
		return nil, err
	}

	// Get resource types parameter
	resourceTypes, err := m.parseResourceTypes(cfg.Args)
	if err != nil {
		return nil, err
	}

	// Validate resource types
	if err := common.ValidateResourceTypes(resourceTypes, common.ResrouceIdentifier); err != nil {
		return nil, err
	}

	// Initialize context if not provided
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	// Process based on scope
	var results []plugin.Result
	switch scope.Type {
	case "org":
		results, err = m.processOrganization(ctx, cfg.Args, scope.Value, resourceTypes)
	case "folder":
		results, err = m.processFolder(ctx, cfg.Args, scope.Value, resourceTypes)
	case "project":
		results, err = m.processProject(ctx, cfg.Args, scope.Value, resourceTypes)
	default:
		return nil, fmt.Errorf("invalid scope type: %s", scope.Type)
	}

	if err != nil {
		return nil, err
	}

	return results, nil
}

func (m *GcpListResources) parseScopeArgs(args map[string]any) (*common.ScopeConfig, error) {
	project, _ := args["project"].(string)
	org, _ := args["org"].(string)
	folder, _ := args["folder"].(string)

	scopeCount := 0
	var scope common.ScopeConfig

	if project != "" {
		scopeCount++
		scope = common.ScopeConfig{Type: "project", Value: project}
	}
	if org != "" {
		scopeCount++
		scope = common.ScopeConfig{Type: "org", Value: org}
	}
	if folder != "" {
		scopeCount++
		scope = common.ScopeConfig{Type: "folder", Value: folder}
	}

	if scopeCount == 0 {
		return nil, fmt.Errorf("one of project, org, or folder must be specified")
	}
	if scopeCount > 1 {
		return nil, fmt.Errorf("only one of project, org, or folder can be specified")
	}

	return &scope, nil
}

func (m *GcpListResources) parseResourceTypes(args map[string]any) ([]string, error) {
	// Try as []string first
	if resourceTypes, ok := args["type"].([]string); ok {
		return resourceTypes, nil
	}

	// Try as string and split
	if typeStr, ok := args["type"].(string); ok {
		if typeStr == "" {
			return []string{"all"}, nil
		}
		return []string{typeStr}, nil
	}

	// Default to all
	return []string{"all"}, nil
}

func (m *GcpListResources) shouldSendResource(resourceTypes []string, resourceType tab.CloudResourceType) bool {
	if len(resourceTypes) == 0 || resourceTypes[0] == "all" {
		return true
	}
	for _, rt := range resourceTypes {
		if rt == resourceType.String() {
			return true
		}
		if common.ResrouceIdentifier(rt) == resourceType {
			return true
		}
	}
	return false
}

func (m *GcpListResources) shouldFanOutToResources(resourceTypes []string) bool {
	if len(resourceTypes) == 0 || resourceTypes[0] == "all" {
		return true
	}
	for _, rt := range resourceTypes {
		resType := common.ResrouceIdentifier(rt)
		if resType != tab.GCPResourceOrganization &&
			resType != tab.GCPResourceFolder &&
			resType != tab.GCPResourceProject {
			return true
		}
	}
	return false
}

func (m *GcpListResources) processOrganization(ctx context.Context, args map[string]any, orgValue string, resourceTypes []string) ([]plugin.Result, error) {
	var results []plugin.Result

	// Phase 1: Get organization info
	orgInfoLink := hierarchy.NewGcpOrgInfoLink(args)
	orgResults, err := orgInfoLink.Process(ctx, orgValue)
	if err != nil {
		return nil, fmt.Errorf("failed to get organization info: %w", err)
	}
	if len(orgResults) == 0 {
		return nil, fmt.Errorf("organization not found: %s", orgValue)
	}

	orgResource, ok := orgResults[0].(output.CloudResource)
	if !ok {
		return nil, fmt.Errorf("unexpected organization result type: %T", orgResults[0])
	}

	// Send organization if requested
	if m.shouldSendResource(resourceTypes, tab.GCPResourceOrganization) {
		results = append(results, plugin.Result{Data: orgResource})
	}

	// Phase 2: List folders if requested
	if m.shouldSendResource(resourceTypes, tab.GCPResourceFolder) {
		folderListLink := hierarchy.NewGcpOrgFolderListLink(args)
		folderResults, err := folderListLink.Process(ctx, orgResource)
		if err != nil {
			return nil, fmt.Errorf("failed to list folders in organization: %w", err)
		}
		for _, folderResult := range folderResults {
			if folder, ok := folderResult.(output.CloudResource); ok {
				results = append(results, plugin.Result{Data: folder})
			}
		}
	}

	// Phase 3: List projects
	projectListLink := hierarchy.NewGcpOrgProjectListLink(args)
	projectResults, err := projectListLink.Process(ctx, orgResource)
	if err != nil {
		return nil, fmt.Errorf("failed to list projects: %w", err)
	}

	// Process each project
	for _, projectResult := range projectResults {
		project, ok := projectResult.(output.CloudResource)
		if !ok {
			continue
		}

		// Send project if requested
		if m.shouldSendResource(resourceTypes, tab.GCPResourceProject) {
			results = append(results, plugin.Result{Data: project})
		}

		// Fan out to resources if needed
		if m.shouldFanOutToResources(resourceTypes) {
			projectResources, err := m.fanOutToResources(ctx, args, project, resourceTypes)
			if err != nil {
				slog.Warn("Some resources failed for project (continuing with others)", "project", project.DisplayName, "error", err)
			}
			results = append(results, projectResources...)
		}
	}

	return results, nil
}

func (m *GcpListResources) processFolder(ctx context.Context, args map[string]any, folderValue string, resourceTypes []string) ([]plugin.Result, error) {
	var results []plugin.Result

	// Phase 1: Get folder info
	folderInfoLink := hierarchy.NewGcpFolderInfoLink(args)
	folderResults, err := folderInfoLink.Process(ctx, folderValue)
	if err != nil {
		return nil, fmt.Errorf("failed to get folder info: %w", err)
	}
	if len(folderResults) == 0 {
		return nil, fmt.Errorf("folder not found: %s", folderValue)
	}

	folderResource, ok := folderResults[0].(output.CloudResource)
	if !ok {
		return nil, fmt.Errorf("unexpected folder result type: %T", folderResults[0])
	}

	// Send folder if requested
	if m.shouldSendResource(resourceTypes, tab.GCPResourceFolder) {
		results = append(results, plugin.Result{Data: folderResource})
	}

	// Phase 2: List subfolders if requested
	if m.shouldSendResource(resourceTypes, tab.GCPResourceFolder) {
		subfolderListLink := hierarchy.NewGcpFolderSubFolderListLink(args)
		subfolderResults, err := subfolderListLink.Process(ctx, folderResource)
		if err != nil {
			return nil, fmt.Errorf("failed to list subfolders in folder: %w", err)
		}
		for _, subfolderResult := range subfolderResults {
			if subfolder, ok := subfolderResult.(output.CloudResource); ok {
				results = append(results, plugin.Result{Data: subfolder})
			}
		}
	}

	// Phase 3: List projects
	projectListLink := hierarchy.NewGcpFolderProjectListLink(args)
	projectResults, err := projectListLink.Process(ctx, folderResource)
	if err != nil {
		return nil, fmt.Errorf("failed to list projects: %w", err)
	}

	// Process each project
	for _, projectResult := range projectResults {
		project, ok := projectResult.(output.CloudResource)
		if !ok {
			continue
		}

		// Send project if requested
		if m.shouldSendResource(resourceTypes, tab.GCPResourceProject) {
			results = append(results, plugin.Result{Data: project})
		}

		// Fan out to resources if needed
		if m.shouldFanOutToResources(resourceTypes) {
			projectResources, err := m.fanOutToResources(ctx, args, project, resourceTypes)
			if err != nil {
				slog.Warn("Some resources failed for project (continuing with others)", "project", project.DisplayName, "error", err)
			}
			results = append(results, projectResources...)
		}
	}

	return results, nil
}

func (m *GcpListResources) processProject(ctx context.Context, args map[string]any, projectValue string, resourceTypes []string) ([]plugin.Result, error) {
	var results []plugin.Result

	// Phase 1: Get project info
	projectInfoLink := hierarchy.NewGcpProjectInfoLink(args)
	projectResults, err := projectInfoLink.Process(ctx, projectValue)
	if err != nil {
		return nil, fmt.Errorf("failed to get project info: %w", err)
	}
	if len(projectResults) == 0 {
		return nil, fmt.Errorf("project not found: %s", projectValue)
	}

	projectResource, ok := projectResults[0].(output.CloudResource)
	if !ok {
		return nil, fmt.Errorf("unexpected project result type: %T", projectResults[0])
	}

	// Send project if requested
	if m.shouldSendResource(resourceTypes, tab.GCPResourceProject) {
		results = append(results, plugin.Result{Data: projectResource})
	}

	// Phase 2: Fan out to resources if needed
	if m.shouldFanOutToResources(resourceTypes) {
		projectResources, err := m.fanOutToResources(ctx, args, projectResource, resourceTypes)
		if err != nil {
			return nil, err
		}
		results = append(results, projectResources...)
	}

	return results, nil
}

func (m *GcpListResources) fanOutToResources(ctx context.Context, args map[string]any, project output.CloudResource, resourceTypes []string) ([]plugin.Result, error) {
	var results []plugin.Result
	var lastError error

	// Build list of links to process based on resource types
	links := m.buildResourceLinks(resourceTypes)
	if len(links) == 0 {
		slog.Debug("No resource types to scan", "project", project.DisplayName)
		return results, nil
	}

	// Process each link sequentially
	for _, link := range links {
		linkResults, err := link.Process(ctx, project)
		if err != nil {
			slog.Warn("Resource link failed (continuing)", "project", project.DisplayName, "error", err)
			lastError = err

			// Parse and send error resources
			resourceErrors := common.ParseAggregatedListError(project.ResourceID, err.Error())
			for _, resourceError := range resourceErrors {
				results = append(results, plugin.Result{Data: resourceError})
			}
			continue
		}

		// Add successful results
		for _, result := range linkResults {
			if cloudResource, ok := result.(output.CloudResource); ok {
				results = append(results, plugin.Result{Data: cloudResource})
			}
		}
	}

	return results, lastError
}

// gcpLink is a local interface for GCP links that can process resources
type gcpLink interface {
	Process(ctx context.Context, input any) ([]any, error)
}

func (m *GcpListResources) buildResourceLinks(resourceTypes []string) []gcpLink {
	var links []gcpLink
	includeAll := len(resourceTypes) == 0 || resourceTypes[0] == "all"

	shouldInclude := func(resourceType string) bool {
		if includeAll {
			return true
		}
		for _, rt := range resourceTypes {
			if rt == resourceType {
				return true
			}
			if common.ResrouceIdentifier(rt) == common.ResrouceIdentifier(resourceType) {
				return true
			}
		}
		return false
	}

	// Storage resources
	if shouldInclude("bucket") {
		links = append(links, storage.NewGcpStorageBucketListLink(nil))
	}
	if shouldInclude("sql") {
		links = append(links, storage.NewGcpSQLInstanceListLink(nil))
	}

	// Compute resources
	if shouldInclude("instance") || shouldInclude("vm") {
		links = append(links, compute.NewGcpInstanceListLink(nil))
	}

	// Networking resources
	if shouldInclude("forwardingrule") || shouldInclude("globalforwardingrule") ||
		shouldInclude("address") || shouldInclude("dnszone") || shouldInclude("managedzone") {
		links = append(links, compute.NewGCPNetworkingFanOut(nil))
	}

	// Application resources
	if shouldInclude("function") || shouldInclude("functionv2") || shouldInclude("functionv1") || shouldInclude("cloudfunction") {
		links = append(links, applications.NewGcpFunctionListLink(nil))
	}
	if shouldInclude("runservice") || shouldInclude("cloudrunservice") {
		links = append(links, applications.NewGcpCloudRunServiceListLink(nil))
	}
	if shouldInclude("appengineservice") {
		links = append(links, applications.NewGcpAppEngineApplicationListLink(nil))
	}

	// Container resources (combined in one link chain)
	if shouldInclude("artifactrepo") || shouldInclude("containerimage") ||
		shouldInclude("dockerimage") || shouldInclude("artifactoryimage") {
		repoLink := containers.NewGcpRepositoryListLink(nil)
		imageLink := containers.NewGcpContainerImageListLink(nil)
		// Chain them together manually
		links = append(links, repoLink, imageLink)
	}

	return links
}
