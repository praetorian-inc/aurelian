package hierarchy

import (
	"context"
	"fmt"
	"strconv"

	"github.com/praetorian-inc/aurelian/pkg/links/gcp/base"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"google.golang.org/api/cloudresourcemanager/v1"
)

// FILE INFO:
// GcpProjectInfoLink - get info of a single project, Process(projectId string)

type GcpProjectInfoLink struct {
	*base.NativeGCPLink
}

// creates a link to get info of a single project
func NewGcpProjectInfoLink(args map[string]any) *GcpProjectInfoLink {
	return &GcpProjectInfoLink{
		NativeGCPLink: base.NewNativeGCPLink("gcp-project-info", args),
	}
}

func (g *GcpProjectInfoLink) Parameters() []plugin.Parameter {
	params := append(base.StandardGCPParams(),
		plugin.NewParam[string]("project", "GCP project ID", plugin.WithRequired()),
	)
	return params
}

func (g *GcpProjectInfoLink) Process(ctx context.Context, input any) ([]any, error) {
	projectId, ok := input.(string)
	if !ok {
		return nil, fmt.Errorf("expected string input, got %T", input)
	}

	resourceManagerService, err := cloudresourcemanager.NewService(ctx, g.ClientOptions()...)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource manager service: %w", err)
	}

	project, err := resourceManagerService.Projects.Get(projectId).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get project %s: %w", projectId, err)
	}
	gcpProject, err := createGcpProjectResource(project)
	if err != nil {
		return nil, err
	}
	return []any{gcpProject}, nil
}

// ---------------------------------------------------------------------------------------------------------------------
// helper functions

func createGcpProjectResource(project *cloudresourcemanager.Project) (*output.CloudResource, error) {
	return &output.CloudResource{
		Platform:     "gcp",
		ResourceType: "cloudresourcemanager.googleapis.com/Project",
		ResourceID:   fmt.Sprintf("projects/%s", project.ProjectId),
		AccountRef:   fmt.Sprintf("%s/%s", project.Parent.Type, project.Parent.Id),
		DisplayName:  project.Name,
		Properties:   linkPostProcessProject(project),
	}, nil
}

func linkPostProcessProject(project *cloudresourcemanager.Project) map[string]any {
	properties := map[string]any{
		"projectNumber":  strconv.FormatInt(project.ProjectNumber, 10), // using string for sanity
		"lifecycleState": project.LifecycleState,
		"parentType":     project.Parent.Type,
		"parentId":       project.Parent.Id,
		"labels":         project.Labels,
	}
	return properties
}
