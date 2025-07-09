package hierarchy

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/cloudresourcemanager/v1"
)

// GcpProjectLister lists all projects (not scoped to any parent)
type GcpProjectLister struct {
	*base.GcpBaseLink
	resourceManagerService *cloudresourcemanager.Service
	FilterSysProjects      bool
}

func NewGcpProjectLister(configs ...cfg.Config) chain.Link {
	g := &GcpProjectLister{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpProjectLister) Params() []cfg.Param {
	params := append(g.GcpBaseLink.Params(),
		cfg.NewParam[bool]("filter-sys-projects", "Filter out system projects like Apps Script projects").WithDefault(true),
	)
	return params
}

func (g *GcpProjectLister) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.resourceManagerService, err = cloudresourcemanager.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create resource manager service: %w", err)
	}
	filterSysProjects, err := cfg.As[bool](g.Arg("filter-sys-projects"))
	if err != nil {
		return fmt.Errorf("failed to get filter-sys-projects: %w", err)
	}
	g.FilterSysProjects = filterSysProjects
	return nil
}

func (g *GcpProjectLister) Process() error {
	slog.Debug("Listing all GCP projects", "filterSysProjects", g.FilterSysProjects)
	listReq := g.resourceManagerService.Projects.List()
	err := listReq.Pages(context.Background(), func(page *cloudresourcemanager.ListProjectsResponse) error {
		for _, project := range page.Projects {
			if g.FilterSysProjects && g.isSysProject(project) {
				slog.Debug("Skipping system project", "projectId", project.ProjectId, "name", project.Name)
				continue
			}
			properties := map[string]any{
				"projectId":      project.ProjectId,
				"name":           project.Name,
				"projectNumber":  project.ProjectNumber,
				"lifecycleState": project.LifecycleState,
				"createTime":     project.CreateTime,
				"parent":         project.Parent,
				"labels":         project.Labels,
			}
			gcpProject, err := tab.NewGCPResource(
				project.ProjectId,      // resource name
				project.ProjectId,      // accountRef (project is its own account ref)
				tab.GCPResourceProject, // resource type
				properties,             // properties
			)
			if err != nil {
				slog.Error("Failed to create GCP project resource", "error", err, "projectId", project.ProjectId)
				continue
			}
			slog.Debug("Found project", "projectId", project.ProjectId, "name", project.Name, "state", project.LifecycleState)
			g.Send(gcpProject)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to list projects: %w", err)
	}
	return nil
}

// projects that should be filtered out
func (g *GcpProjectLister) isSysProject(project *cloudresourcemanager.Project) bool {
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
