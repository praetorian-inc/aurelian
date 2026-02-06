package recon

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/aurelian/internal/secrets"
	"github.com/praetorian-inc/aurelian/pkg/links/gcp/applications"
	"github.com/praetorian-inc/aurelian/pkg/links/gcp/common"
	"github.com/praetorian-inc/aurelian/pkg/links/gcp/compute"
	"github.com/praetorian-inc/aurelian/pkg/links/gcp/containers"
	"github.com/praetorian-inc/aurelian/pkg/links/gcp/hierarchy"
	"github.com/praetorian-inc/aurelian/pkg/links/gcp/storage"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	plugin.Register(&GcpFindSecrets{})
}

// GcpFindSecrets scans GCP resources for secrets using NoseyParker
type GcpFindSecrets struct{}

// Metadata methods
func (m *GcpFindSecrets) ID() string {
	return "find-secrets"
}

func (m *GcpFindSecrets) Name() string {
	return "GCP Find Secrets"
}

func (m *GcpFindSecrets) Description() string {
	return `Scan GCP resources for secrets using NoseyParker across organization, folder, or project scope with optional resource type filtering.

This module scans various GCP resource types for secrets, credentials, and sensitive information using NoseyParker scanner:

**Supported Resource Types:**
- **bucket**: Storage buckets and objects
- **instance** / **vm**: Compute Engine instances
- **function** / **cloudfunction**: Cloud Functions (v1 and v2)
- **runservice** / **cloudrunservice**: Cloud Run services
- **appengineservice**: App Engine services
- **containerimage** / **dockerimage**: Container images in Artifact Registry

**Scope Options:**
- Organization-level: Scan all projects in an organization
- Folder-level: Scan all projects in a folder
- Project-level: Scan a single project

**Detection Method:**
1. Resolves scope (org/folder/project) to project list
2. For each project, scans selected resource types
3. Extracts content from resources and pipes to NoseyParker
4. Reports findings with context and severity

The module provides detailed secret findings including type, location, and risk assessment.`
}

func (m *GcpFindSecrets) Platform() plugin.Platform {
	return plugin.PlatformGCP
}

func (m *GcpFindSecrets) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *GcpFindSecrets) OpsecLevel() string {
	return "moderate"
}

func (m *GcpFindSecrets) Authors() []string {
	return []string{"Praetorian"}
}

func (m *GcpFindSecrets) References() []string {
	return []string{}
}

func (m *GcpFindSecrets) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "org",
			Description: "GCP organization name or ID (mutually exclusive with folder/project)",
			Type:        "string",
			Required:    false,
		},
		{
			Name:        "folder",
			Description: "GCP folder name or ID (mutually exclusive with org/project)",
			Type:        "string",
			Required:    false,
		},
		{
			Name:        "project",
			Description: "GCP project name or ID (mutually exclusive with org/folder)",
			Type:        "string",
			Required:    false,
		},
		{
			Name:        "type",
			Description: "Resource types to scan (comma-separated: bucket,instance,function,runservice,appengineservice,containerimage; default: all)",
			Type:        "[]string",
			Required:    false,
			Default:     []string{},
		},
		{
			Name:        "include-sys-projects",
			Description: "Include system projects in scan",
			Type:        "bool",
			Required:    false,
			Default:     true,
		},
	}
}

// Run executes the secrets scanning module
func (m *GcpFindSecrets) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Initialize context
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	// Parse scope configuration
	scope, err := common.ParseScopeArgs(cfg.Args)
	if err != nil {
		return nil, fmt.Errorf("invalid scope configuration: %w", err)
	}

	// Parse and validate resource types
	resourceTypes, _ := cfg.Args["type"].([]string)
	if err := common.ValidateResourceTypes(resourceTypes, common.SecretsResourceIdentifier); err != nil {
		return nil, err
	}

	slog.Info("Starting secrets scan", "scope_type", scope.Type, "scope_value", scope.Value, "resource_types", resourceTypes)

	// Route to appropriate scope handler
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
		return nil, fmt.Errorf("secrets scan failed: %w", err)
	}

	return results, nil
}

// processOrganization scans all projects in an organization
func (m *GcpFindSecrets) processOrganization(ctx context.Context, args map[string]any, orgName string, resourceTypes []string) ([]plugin.Result, error) {
	// Get organization info
	orgInfoLink := hierarchy.NewGcpOrgInfoLink(args)
	orgResults, err := orgInfoLink.Process(ctx, orgName)
	if err != nil {
		return nil, fmt.Errorf("failed to get organization info: %w", err)
	}
	if len(orgResults) == 0 {
		return nil, fmt.Errorf("no organization found for: %s", orgName)
	}

	orgResource, ok := orgResults[0].(output.CloudResource)
	if !ok {
		return nil, fmt.Errorf("unexpected organization result type: %T", orgResults[0])
	}

	slog.Info("Processing organization", "org", orgResource.ResourceID, "name", orgResource.DisplayName)

	// List projects in organization
	includeSysProjects, _ := args["include-sys-projects"].(bool)
	projectListLink := hierarchy.NewGcpOrgProjectListLink(map[string]any{
		"filter-sys-projects": !includeSysProjects,
	})
	projectResults, err := projectListLink.Process(ctx, orgResource)
	if err != nil {
		return nil, fmt.Errorf("failed to list projects: %w", err)
	}

	slog.Info("Found projects", "count", len(projectResults))

	// Scan each project
	var allResults []plugin.Result
	for _, projectResult := range projectResults {
		projectResource, ok := projectResult.(output.CloudResource)
		if !ok {
			slog.Warn("Skipping non-CloudResource project result", "type", fmt.Sprintf("%T", projectResult))
			continue
		}

		projectResults, err := m.scanProjectSecrets(ctx, args, projectResource, resourceTypes)
		if err != nil {
			slog.Warn("Failed to scan project (continuing with others)", "project", projectResource.ResourceID, "error", err)
			continue
		}
		allResults = append(allResults, projectResults...)
	}

	return allResults, nil
}

// processFolder scans all projects in a folder
func (m *GcpFindSecrets) processFolder(ctx context.Context, args map[string]any, folderName string, resourceTypes []string) ([]plugin.Result, error) {
	// Get folder info
	folderInfoLink := hierarchy.NewGcpFolderInfoLink(args)
	folderResults, err := folderInfoLink.Process(ctx, folderName)
	if err != nil {
		return nil, fmt.Errorf("failed to get folder info: %w", err)
	}
	if len(folderResults) == 0 {
		return nil, fmt.Errorf("no folder found for: %s", folderName)
	}

	folderResource, ok := folderResults[0].(output.CloudResource)
	if !ok {
		return nil, fmt.Errorf("unexpected folder result type: %T", folderResults[0])
	}

	slog.Info("Processing folder", "folder", folderResource.ResourceID, "name", folderResource.DisplayName)

	// List projects in folder
	includeSysProjects, _ := args["include-sys-projects"].(bool)
	projectListLink := hierarchy.NewGcpFolderProjectListLink(map[string]any{
		"filter-sys-projects": !includeSysProjects,
	})
	projectResults, err := projectListLink.Process(ctx, folderResource)
	if err != nil {
		return nil, fmt.Errorf("failed to list projects: %w", err)
	}

	slog.Info("Found projects", "count", len(projectResults))

	// Scan each project
	var allResults []plugin.Result
	for _, projectResult := range projectResults {
		projectResource, ok := projectResult.(output.CloudResource)
		if !ok {
			slog.Warn("Skipping non-CloudResource project result", "type", fmt.Sprintf("%T", projectResult))
			continue
		}

		projectResults, err := m.scanProjectSecrets(ctx, args, projectResource, resourceTypes)
		if err != nil {
			slog.Warn("Failed to scan project (continuing with others)", "project", projectResource.ResourceID, "error", err)
			continue
		}
		allResults = append(allResults, projectResults...)
	}

	return allResults, nil
}

// processProject scans a single project
func (m *GcpFindSecrets) processProject(ctx context.Context, args map[string]any, projectName string, resourceTypes []string) ([]plugin.Result, error) {
	// Get project info
	projectInfoLink := hierarchy.NewGcpProjectInfoLink(args)
	projectResults, err := projectInfoLink.Process(ctx, projectName)
	if err != nil {
		return nil, fmt.Errorf("failed to get project info: %w", err)
	}
	if len(projectResults) == 0 {
		return nil, fmt.Errorf("no project found for: %s", projectName)
	}

	projectResource, ok := projectResults[0].(output.CloudResource)
	if !ok {
		return nil, fmt.Errorf("unexpected project result type: %T", projectResults[0])
	}

	return m.scanProjectSecrets(ctx, args, projectResource, resourceTypes)
}

// scanProjectSecrets orchestrates scanning of all resource types in a project
func (m *GcpFindSecrets) scanProjectSecrets(ctx context.Context, args map[string]any, project output.CloudResource, resourceTypes []string) ([]plugin.Result, error) {
	slog.Info("Scanning project for secrets", "project", project.ResourceID, "name", project.DisplayName)

	if len(resourceTypes) == 0 {
		slog.Debug("No resource types specified, defaulting to all")
	}

	var allResults []plugin.Result
	includeAll := len(resourceTypes) == 0 || resourceTypes[0] == "all"

	shouldInclude := func(resourceType string) bool {
		if includeAll {
			return true
		}
		for _, rt := range resourceTypes {
			if rt == resourceType {
				return true
			}
			if common.SecretsResourceIdentifier(rt) == common.SecretsResourceIdentifier(resourceType) {
				return true
			}
		}
		return false
	}

	// Storage buckets
	if shouldInclude("bucket") {
		results, err := m.scanStorageBuckets(ctx, args, project)
		if err != nil {
			slog.Warn("Failed to scan storage buckets", "project", project.ResourceID, "error", err)
		} else {
			allResults = append(allResults, results...)
		}
	}

	// Compute instances
	if shouldInclude("instance") || shouldInclude("vm") {
		results, err := m.scanComputeInstances(ctx, args, project)
		if err != nil {
			slog.Warn("Failed to scan compute instances", "project", project.ResourceID, "error", err)
		} else {
			allResults = append(allResults, results...)
		}
	}

	// Cloud Functions
	if shouldInclude("function") || shouldInclude("functionv2") || shouldInclude("functionv1") || shouldInclude("cloudfunction") {
		results, err := m.scanCloudFunctions(ctx, args, project)
		if err != nil {
			slog.Warn("Failed to scan cloud functions", "project", project.ResourceID, "error", err)
		} else {
			allResults = append(allResults, results...)
		}
	}

	// Cloud Run services
	if shouldInclude("runservice") || shouldInclude("cloudrunservice") {
		results, err := m.scanCloudRun(ctx, args, project)
		if err != nil {
			slog.Warn("Failed to scan cloud run services", "project", project.ResourceID, "error", err)
		} else {
			allResults = append(allResults, results...)
		}
	}

	// App Engine services
	if shouldInclude("appengineservice") {
		results, err := m.scanAppEngine(ctx, args, project)
		if err != nil {
			slog.Warn("Failed to scan app engine services", "project", project.ResourceID, "error", err)
		} else {
			allResults = append(allResults, results...)
		}
	}

	// Container images
	if shouldInclude("containerimage") || shouldInclude("dockerimage") || shouldInclude("artifactoryimage") {
		results, err := m.scanContainerImages(ctx, args, project)
		if err != nil {
			slog.Warn("Failed to scan container images", "project", project.ResourceID, "error", err)
		} else {
			allResults = append(allResults, results...)
		}
	}

	slog.Info("Project scan complete", "project", project.ResourceID, "findings", len(allResults))
	return allResults, nil
}

// Resource-specific scanning functions

func (m *GcpFindSecrets) scanStorageBuckets(ctx context.Context, args map[string]any, project output.CloudResource) ([]plugin.Result, error) {
	// List buckets
	bucketListLink := storage.NewGcpStorageBucketListLink(args)
	bucketResults, err := bucketListLink.Process(ctx, project)
	if err != nil {
		return nil, fmt.Errorf("failed to list storage buckets: %w", err)
	}

	var allResults []plugin.Result
	for _, bucketResult := range bucketResults {
		bucketResource, ok := bucketResult.(output.CloudResource)
		if !ok {
			continue
		}

		// List objects in bucket
		objectListLink := storage.NewGcpStorageObjectListLink(args)
		objectResults, err := objectListLink.Process(ctx, bucketResource)
		if err != nil {
			slog.Warn("Failed to list objects in bucket", "bucket", bucketResource.ResourceID, "error", err)
			continue
		}

		// Scan objects for secrets
		for _, objectResult := range objectResults {
			objectResource, ok := objectResult.(output.CloudResource)
			if !ok {
				continue
			}

			secretsLink := storage.NewGcpStorageObjectSecretsLink(args)
			secretResults, err := secretsLink.Process(ctx, objectResource)
			if err != nil {
				slog.Debug("Failed to scan object for secrets", "object", objectResource.ResourceID, "error", err)
				continue
			}

			// Pipe through NoseyParker
			for _, secretResult := range secretResults {
				npResults, err := m.scanWithNoseyParker(ctx, args, secretResult)
				if err != nil {
					slog.Debug("NoseyParker scan failed", "error", err)
					continue
				}
				allResults = append(allResults, npResults...)
			}
		}
	}

	return allResults, nil
}

func (m *GcpFindSecrets) scanComputeInstances(ctx context.Context, args map[string]any, project output.CloudResource) ([]plugin.Result, error) {
	// List instances
	instanceListLink := compute.NewGcpInstanceListLink(args)
	instanceResults, err := instanceListLink.Process(ctx, project)
	if err != nil {
		return nil, fmt.Errorf("failed to list compute instances: %w", err)
	}

	var allResults []plugin.Result
	for _, instanceResult := range instanceResults {
		instanceResource, ok := instanceResult.(output.CloudResource)
		if !ok {
			continue
		}

		// Extract secrets from instance
		secretsLink := compute.NewGcpInstanceSecretsLink(args)
		secretResults, err := secretsLink.Process(ctx, instanceResource)
		if err != nil {
			slog.Debug("Failed to scan instance for secrets", "instance", instanceResource.ResourceID, "error", err)
			continue
		}

		// Pipe through NoseyParker
		for _, secretResult := range secretResults {
			npResults, err := m.scanWithNoseyParker(ctx, args, secretResult)
			if err != nil {
				slog.Debug("NoseyParker scan failed", "error", err)
				continue
			}
			allResults = append(allResults, npResults...)
		}
	}

	return allResults, nil
}

func (m *GcpFindSecrets) scanCloudFunctions(ctx context.Context, args map[string]any, project output.CloudResource) ([]plugin.Result, error) {
	// List functions
	functionListLink := applications.NewGcpFunctionListLink()
	functionResults, err := functionListLink.Process(ctx, project)
	if err != nil {
		return nil, fmt.Errorf("failed to list cloud functions: %w", err)
	}

	var allResults []plugin.Result
	for _, functionResult := range functionResults {
		functionResource, ok := functionResult.(output.CloudResource)
		if !ok {
			continue
		}

		// Extract secrets from function
		secretsLink := applications.NewGcpFunctionSecretsLink()
		secretResults, err := secretsLink.Process(ctx, functionResource)
		if err != nil {
			slog.Debug("Failed to scan function for secrets", "function", functionResource.ResourceID, "error", err)
			continue
		}

		// Pipe through NoseyParker
		for _, secretResult := range secretResults {
			npResults, err := m.scanWithNoseyParker(ctx, args, secretResult)
			if err != nil {
				slog.Debug("NoseyParker scan failed", "error", err)
				continue
			}
			allResults = append(allResults, npResults...)
		}
	}

	return allResults, nil
}

func (m *GcpFindSecrets) scanCloudRun(ctx context.Context, args map[string]any, project output.CloudResource) ([]plugin.Result, error) {
	// List Cloud Run services
	serviceListLink := applications.NewGcpCloudRunServiceListLink()
	serviceResults, err := serviceListLink.Process(ctx, project)
	if err != nil {
		return nil, fmt.Errorf("failed to list cloud run services: %w", err)
	}

	var allResults []plugin.Result
	for _, serviceResult := range serviceResults {
		serviceResource, ok := serviceResult.(output.CloudResource)
		if !ok {
			continue
		}

		// Extract secrets from service
		secretsLink := applications.NewGcpCloudRunSecretsLink()
		secretResults, err := secretsLink.Process(ctx, serviceResource)
		if err != nil {
			slog.Debug("Failed to scan cloud run service for secrets", "service", serviceResource.ResourceID, "error", err)
			continue
		}

		// Pipe through NoseyParker
		for _, secretResult := range secretResults {
			npResults, err := m.scanWithNoseyParker(ctx, args, secretResult)
			if err != nil {
				slog.Debug("NoseyParker scan failed", "error", err)
				continue
			}
			allResults = append(allResults, npResults...)
		}
	}

	return allResults, nil
}

func (m *GcpFindSecrets) scanAppEngine(ctx context.Context, args map[string]any, project output.CloudResource) ([]plugin.Result, error) {
	// List App Engine applications
	appListLink := applications.NewGcpAppEngineApplicationListLink()
	appResults, err := appListLink.Process(ctx, project)
	if err != nil {
		return nil, fmt.Errorf("failed to list app engine applications: %w", err)
	}

	var allResults []plugin.Result
	for _, appResult := range appResults {
		appResource, ok := appResult.(output.CloudResource)
		if !ok {
			continue
		}

		// Extract secrets from application
		secretsLink := applications.NewGcpAppEngineSecretsLink()
		secretResults, err := secretsLink.Process(ctx, appResource)
		if err != nil {
			slog.Debug("Failed to scan app engine application for secrets", "application", appResource.ResourceID, "error", err)
			continue
		}

		// Pipe through NoseyParker
		for _, secretResult := range secretResults {
			npResults, err := m.scanWithNoseyParker(ctx, args, secretResult)
			if err != nil {
				slog.Debug("NoseyParker scan failed", "error", err)
				continue
			}
			allResults = append(allResults, npResults...)
		}
	}

	return allResults, nil
}

func (m *GcpFindSecrets) scanContainerImages(ctx context.Context, args map[string]any, project output.CloudResource) ([]plugin.Result, error) {
	// List repositories
	repoListLink := containers.NewGcpRepositoryListLink(args)
	repoResults, err := repoListLink.Process(ctx, project)
	if err != nil {
		return nil, fmt.Errorf("failed to list container repositories: %w", err)
	}

	var allResults []plugin.Result
	for _, repoResult := range repoResults {
		repoResource, ok := repoResult.(output.CloudResource)
		if !ok {
			continue
		}

		// List images in repository
		imageListLink := containers.NewGcpContainerImageListLink(args)
		imageResults, err := imageListLink.Process(ctx, repoResource)
		if err != nil {
			slog.Warn("Failed to list images in repository", "repository", repoResource.ResourceID, "error", err)
			continue
		}

		// Scan images for secrets
		for _, imageResult := range imageResults {
			imageResource, ok := imageResult.(output.CloudResource)
			if !ok {
				continue
			}

			secretsLink := containers.NewGcpContainerImageSecretsLink(args)
			secretResults, err := secretsLink.Process(ctx, imageResource)
			if err != nil {
				slog.Debug("Failed to scan container image for secrets", "image", imageResource.ResourceID, "error", err)
				continue
			}

			// Pipe through NoseyParker
			for _, secretResult := range secretResults {
				npResults, err := m.scanWithNoseyParker(ctx, args, secretResult)
				if err != nil {
					slog.Debug("NoseyParker scan failed", "error", err)
					continue
				}
				allResults = append(allResults, npResults...)
			}
		}
	}

	return allResults, nil
}

// scanWithNoseyParker pipes results through NoseyParker scanner
func (m *GcpFindSecrets) scanWithNoseyParker(ctx context.Context, args map[string]any, input any) ([]plugin.Result, error) {
	// Convert input to NpInput format
	npInput, ok := input.(types.NpInput)
	if !ok {
		return nil, fmt.Errorf("expected types.NpInput, got %T", input)
	}

	// Create scanner
	scanner, err := secrets.NewNPScanner()
	if err != nil {
		return nil, fmt.Errorf("failed to create noseyparker scanner: %w", err)
	}
	defer scanner.Cleanup()

	// Scan content
	findings, err := scanner.ScanContent(ctx, []types.NpInput{npInput})
	if err != nil {
		return nil, fmt.Errorf("noseyparker scan failed: %w", err)
	}

	// Convert findings to plugin results
	var results []plugin.Result
	for _, finding := range findings {
		results = append(results, plugin.Result{
			Data: finding,
			Metadata: map[string]any{
				"module":      "find-secrets",
				"platform":    "gcp",
				"category":    "recon",
				"opsec_level": "moderate",
			},
		})
	}

	return results, nil
}
