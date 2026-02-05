package hierarchy

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/links/gcp/base"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"google.golang.org/api/cloudresourcemanager/v1"
	cloudresourcemanagerv2 "google.golang.org/api/cloudresourcemanager/v2"
)

// FILE INFO:
// GcpFolderInfoLink - get info of a single folder, Process(folderName string)
// GcpFolderSubFolderListLink - list all folders in a folder, Process(resource output.CloudResource); needs folder
// GcpFolderProjectListLink - list all projects in a folder, Process(resource output.CloudResource); needs folder

type GcpFolderInfoLink struct {
	*base.NativeGCPLink
}

// creates a link to get info of a single folder
func NewGcpFolderInfoLink(args map[string]any) *GcpFolderInfoLink {
	return &GcpFolderInfoLink{
		NativeGCPLink: base.NewNativeGCPLink("gcp-folder-info", args),
	}
}

func (g *GcpFolderInfoLink) Parameters() []plugin.Parameter {
	params := append(base.StandardGCPParams(),
		plugin.NewParam[string]("folder", "GCP folder name or ID", plugin.WithRequired()),
	)
	return params
}

func (g *GcpFolderInfoLink) Process(ctx context.Context, input any) ([]any, error) {
	folderName, ok := input.(string)
	if !ok {
		return nil, fmt.Errorf("expected string input, got %T", input)
	}

	resourceManagerService, err := cloudresourcemanagerv2.NewService(ctx, g.ClientOptions()...)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource manager v2 service: %w", err)
	}

	folder, err := resourceManagerService.Folders.Get(folderName).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get folder %s: %w", folderName, err)
	}
	gcpFolder, err := createGcpFolderResource(folder)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCP folder resource: %w", err)
	}
	return []any{gcpFolder}, nil
}

type GcpFolderSubFolderListLink struct {
	*base.NativeGCPLink
}

// creates a link to list all folders in a folder
func NewGcpFolderSubFolderListLink(args map[string]any) *GcpFolderSubFolderListLink {
	return &GcpFolderSubFolderListLink{
		NativeGCPLink: base.NewNativeGCPLink("gcp-folder-subfolder-list", args),
	}
}

func (g *GcpFolderSubFolderListLink) Parameters() []plugin.Parameter {
	return base.StandardGCPParams()
}

func (g *GcpFolderSubFolderListLink) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(output.CloudResource)
	if !ok {
		return nil, fmt.Errorf("expected output.CloudResource, got %T", input)
	}

	if resource.ResourceType != "cloudresourcemanager.googleapis.com/Folder" {
		return []any{}, nil
	}

	folderName := resource.ResourceID
	resourceManagerService, err := cloudresourcemanagerv2.NewService(ctx, g.ClientOptions()...)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource manager v2 service: %w", err)
	}

	var results []any
	listReq := resourceManagerService.Folders.List().Parent(folderName)
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
		return nil, fmt.Errorf("failed to list folders in folder %s: %w", folderName, err)
	}
	return results, nil
}

type GcpFolderProjectListLink struct {
	*base.NativeGCPLink
	FilterSysProjects bool
}

// creates a link to list all projects in a folder
func NewGcpFolderProjectListLink(args map[string]any) *GcpFolderProjectListLink {
	link := &GcpFolderProjectListLink{
		NativeGCPLink: base.NewNativeGCPLink("gcp-folder-project-list", args),
	}
	if filterSysProjects, ok := args["filter-sys-projects"].(bool); ok {
		link.FilterSysProjects = filterSysProjects
	}
	return link
}

func (g *GcpFolderProjectListLink) Parameters() []plugin.Parameter {
	params := append(base.StandardGCPParams(),
		plugin.NewParam[bool]("filter-sys-projects", "Filter system projects", plugin.WithDefault(false)),
	)
	return params
}

func (g *GcpFolderProjectListLink) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(output.CloudResource)
	if !ok {
		return nil, fmt.Errorf("expected output.CloudResource, got %T", input)
	}

	if resource.ResourceType != "cloudresourcemanager.googleapis.com/Folder" {
		return []any{}, nil
	}

	folderName := resource.ResourceID
	resourceManagerService, err := cloudresourcemanager.NewService(ctx, g.ClientOptions()...)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource manager service: %w", err)
	}

	var results []any
	listReq := resourceManagerService.Projects.List().Filter(fmt.Sprintf("parent.id:%s", folderName))
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
		return nil, fmt.Errorf("failed to list projects in folder %s: %w", folderName, err)
	}
	return results, nil
}

// ---------------------------------------------------------------------------------------------------------------------
// helper functions

func createGcpFolderResource(folder *cloudresourcemanagerv2.Folder) (*output.CloudResource, error) {
	return &output.CloudResource{
		Platform:     "gcp",
		ResourceType: "cloudresourcemanager.googleapis.com/Folder",
		ResourceID:   folder.Name, // "folders/123456789"
		AccountRef:   folder.Parent,
		DisplayName:  folder.DisplayName,
		Properties:   linkPostProcessFolder(folder),
	}, nil
}

func linkPostProcessFolder(folder *cloudresourcemanagerv2.Folder) map[string]any {
	properties := map[string]any{
		"lifecycleState": folder.LifecycleState,
		"createTime":     folder.CreateTime,
	}
	return properties
}
