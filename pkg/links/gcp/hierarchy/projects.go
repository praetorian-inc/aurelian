package hierarchy

import (
	"context"
	"fmt"
	"strconv"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/cloudresourcemanager/v1"
)

// FILE INFO:
// GcpProjectInfoLink - get info of a single project, Process(projectId string)

type GcpProjectInfoLink struct {
	*base.GcpBaseLink
	resourceManagerService *cloudresourcemanager.Service
}

// creates a link to get info of a single project
func NewGcpProjectInfoLink(configs ...cfg.Config) chain.Link {
	g := &GcpProjectInfoLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpProjectInfoLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.resourceManagerService, err = cloudresourcemanager.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create resource manager service: %w", err)
	}
	return nil
}

func (g *GcpProjectInfoLink) Params() []cfg.Param {
	params := append(g.GcpBaseLink.Params(),
		options.GcpProject(),
	)
	return params
}

func (g *GcpProjectInfoLink) Process(projectId string) error {
	project, err := g.resourceManagerService.Projects.Get(projectId).Do()
	if err != nil {
		return fmt.Errorf("failed to get project %s: %w", projectId, err)
	}
	gcpProject, err := createGcpProjectResource(project)
	if err != nil {
		return err
	}
	g.Send(gcpProject)
	return nil
}

// ---------------------------------------------------------------------------------------------------------------------
// helper functions

func createGcpProjectResource(project *cloudresourcemanager.Project) (*tab.GCPResource, error) {
	gcpProject, err := tab.NewGCPResource(
		project.ProjectId, // resource name (project ID)
		fmt.Sprintf("%s/%s", project.Parent.Type, project.Parent.Id), // accountRef (hierarchy parent)
		tab.GCPResourceProject,          // resource type
		linkPostProcessProject(project), // properties
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCP project resource: %w", err)
	}
	gcpProject.DisplayName = project.Name
	return &gcpProject, nil
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
