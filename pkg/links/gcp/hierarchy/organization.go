package hierarchy

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/links/gcp/base"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"google.golang.org/api/cloudresourcemanager/v1"
	cloudresourcemanagerv2 "google.golang.org/api/cloudresourcemanager/v2"
)

// FILE INFO:
// GcpOrganizationLister - list all organizations
// GcpOrgInfoLink - get info of a single organization, Process(orgName string)
// GcpOrgFolderListLink - list all folders in an organization, Process(resource output.CloudResource); needs organization
// GcpOrgProjectListLink - list all projects in an organization, Process(resource output.CloudResource); needs organization

type GcpOrganizationLister struct {
	*base.NativeGCPLink
}

// creates a link to list all organizations
func NewGcpOrganizationLister(args map[string]any) *GcpOrganizationLister {
	return &GcpOrganizationLister{
		NativeGCPLink: base.NewNativeGCPLink("gcp-organization-lister", args),
	}
}

func (g *GcpOrganizationLister) Process(ctx context.Context, _ any) ([]any, error) {
	// no resource input (meant to be non-contextual)
	resourceManagerService, err := cloudresourcemanager.NewService(ctx, g.ClientOptions()...)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource manager service: %w", err)
	}

	searchReq := resourceManagerService.Organizations.Search(&cloudresourcemanager.SearchOrganizationsRequest{})
	resp, err := searchReq.Do()
	if err != nil {
		return nil, fmt.Errorf("failed to search organizations: %w", err)
	}
	if len(resp.Organizations) == 0 {
		return []any{}, nil
	}

	var results []any
	for _, org := range resp.Organizations {
		gcpOrg, err := createGcpOrgResource(org)
		if err != nil {
			slog.Error("Failed to create GCP organization resource", "error", err, "org", org.Name)
			continue
		}
		results = append(results, gcpOrg)
	}
	return results, nil
}

func (g *GcpOrganizationLister) Parameters() []plugin.Parameter {
	return base.StandardGCPParams()
}

type GcpOrgInfoLink struct {
	*base.NativeGCPLink
}

// creates a link to get info of a single organization
func NewGcpOrgInfoLink(args map[string]any) *GcpOrgInfoLink {
	return &GcpOrgInfoLink{
		NativeGCPLink: base.NewNativeGCPLink("gcp-org-info", args),
	}
}

func (g *GcpOrgInfoLink) Parameters() []plugin.Parameter {
	params := append(base.StandardGCPParams(),
		plugin.NewParam[string]("org", "GCP organization name or ID", plugin.WithRequired()),
	)
	return params
}

func (g *GcpOrgInfoLink) Process(ctx context.Context, input any) ([]any, error) {
	orgName, ok := input.(string)
	if !ok {
		return nil, fmt.Errorf("expected string input, got %T", input)
	}

	if !strings.HasPrefix(orgName, "organizations/") {
		orgName = "organizations/" + orgName
	}

	resourceManagerService, err := cloudresourcemanager.NewService(ctx, g.ClientOptions()...)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource manager service: %w", err)
	}

	org, err := resourceManagerService.Organizations.Get(orgName).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get organization %s: %w", orgName, err)
	}
	gcpOrg, err := createGcpOrgResource(org)
	if err != nil {
		return nil, err
	}
	return []any{gcpOrg}, nil
}

type GcpOrgFolderListLink struct {
	*base.NativeGCPLink
}

// creates a link to list all folders in an organization
func NewGcpOrgFolderListLink(args map[string]any) *GcpOrgFolderListLink {
	return &GcpOrgFolderListLink{
		NativeGCPLink: base.NewNativeGCPLink("gcp-org-folder-list", args),
	}
}

func (g *GcpOrgFolderListLink) Parameters() []plugin.Parameter {
	return base.StandardGCPParams()
}

func (g *GcpOrgFolderListLink) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(output.CloudResource)
	if !ok {
		return nil, fmt.Errorf("expected output.CloudResource, got %T", input)
	}

	if resource.ResourceType != "cloudresourcemanager.googleapis.com/Organization" {
		return []any{}, nil
	}

	orgName := resource.ResourceID
	v2Service, err := cloudresourcemanagerv2.NewService(ctx, g.ClientOptions()...)
	if err != nil {
		return nil, fmt.Errorf("failed to create v2 resource manager service: %w", err)
	}

	var results []any
	listReq := v2Service.Folders.List().Parent(orgName)
	err = listReq.Pages(ctx, func(page *cloudresourcemanagerv2.ListFoldersResponse) error {
		for _, folder := range page.Folders {
			gcpFolder, err := createGcpFolderResource(folder)
			if err != nil {
				slog.Error("Failed to create GCP folder resource", "error", err, "folder", folder.Name)
				continue
			}
			results = append(results, gcpFolder)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list folders in organization %s: %w", orgName, err)
	}
	return results, nil
}

type GcpOrgProjectListLink struct {
	*base.NativeGCPLink
	FilterSysProjects bool
}

// creates a link to list all projects in an organization
func NewGcpOrgProjectListLink(args map[string]any) *GcpOrgProjectListLink {
	link := &GcpOrgProjectListLink{
		NativeGCPLink: base.NewNativeGCPLink("gcp-org-project-list", args),
	}
	if filterSysProjects, ok := args["filter-sys-projects"].(bool); ok {
		link.FilterSysProjects = filterSysProjects
	}
	return link
}

func (g *GcpOrgProjectListLink) Parameters() []plugin.Parameter {
	params := append(base.StandardGCPParams(),
		plugin.NewParam[bool]("filter-sys-projects", "Filter system projects", plugin.WithDefault(false)),
	)
	return params
}

func (g *GcpOrgProjectListLink) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(output.CloudResource)
	if !ok {
		return nil, fmt.Errorf("expected output.CloudResource, got %T", input)
	}

	if resource.ResourceType != "cloudresourcemanager.googleapis.com/Organization" {
		return []any{}, nil
	}

	orgName := resource.ResourceID
	resourceManagerService, err := cloudresourcemanager.NewService(ctx, g.ClientOptions()...)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource manager service: %w", err)
	}

	var results []any
	listReq := resourceManagerService.Projects.List() // .Filter(fmt.Sprintf("parent.id:%s", orgName)) -- TODO: add this back if/when we introduce folder filter in CLI
	err = listReq.Pages(ctx, func(page *cloudresourcemanager.ListProjectsResponse) error {
		for _, project := range page.Projects {
			if g.FilterSysProjects && isSysProject(project) {
				continue
			}
			gcpProject, err := createGcpProjectResource(project)
			if err != nil {
				slog.Error("Failed to create GCP project resource", "error", err, "projectId", project.ProjectId)
				continue
			}
			results = append(results, gcpProject)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list projects in organization %s: %w", orgName, err)
	}
	return results, nil
}

// ---------------------------------------------------------------------------------------------------------------------
// helper functions

func createGcpOrgResource(org *cloudresourcemanager.Organization) (*output.CloudResource, error) {
	return &output.CloudResource{
		Platform:     "gcp",
		ResourceType: "cloudresourcemanager.googleapis.com/Organization",
		ResourceID:   org.Name, // "organizations/123456789"
		AccountRef:   org.Name, // Self-reference for top-level organization
		DisplayName:  org.DisplayName,
		Properties:   linkPostProcessOrg(org),
	}, nil
}

func linkPostProcessOrg(org *cloudresourcemanager.Organization) map[string]any {
	properties := map[string]any{
		"lifecycleState": org.LifecycleState,
		"owner":          org.Owner.DirectoryCustomerId,
	}
	return properties
}

func isSysProject(project *cloudresourcemanager.Project) bool {
	sysPatterns := []string{
		"sys-",
		"script-editor-",
		"apps-script-",
		"system-",      // potentially worth removing
		"firebase-",    // potentially worth removing
		"cloud-build-", // potentially worth removing
		"gcf-",         // potentially worth removing
		"gae-",         // potentially worth removing
	}
	projectId := strings.ToLower(project.ProjectId)
	projectName := strings.ToLower(project.Name)
	for _, pattern := range sysPatterns {
		if strings.HasPrefix(projectId, pattern) || strings.HasPrefix(projectName, pattern) {
			return true
		}
	}
	return false
}
