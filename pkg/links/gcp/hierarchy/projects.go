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

type GcpProjectLister struct {
	*base.GcpReconBaseLink
	resourceManagerService *cloudresourcemanager.Service
	FilterSysProjects      bool
	Filter                 string
}

func NewGcpProjectLister(configs ...cfg.Config) chain.Link {
	g := &GcpProjectLister{}
	g.GcpReconBaseLink = base.NewGcpReconBaseLink(g, configs...)
	return g
}

func (g *GcpProjectLister) Params() []cfg.Param {
	params := g.GcpReconBaseLink.Params()
	params = append(params,
		cfg.NewParam[bool]("filter-sys-projects", "Filter out system projects like Apps Script projects").WithDefault(true),
		cfg.NewParam[string]("filter", "Additional filter to apply to project listing").WithDefault(""),
	)
	return params
}

func (g *GcpProjectLister) Initialize() error {
	if err := g.GcpReconBaseLink.Initialize(); err != nil {
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
	filter, err := cfg.As[string](g.Arg("filter"))
	if err != nil {
		return fmt.Errorf("failed to get filter: %w", err)
	}
	g.Filter = filter
	return nil
}

func (g *GcpProjectLister) Process() error {
	slog.Debug("Listing GCP projects", "filterSysProjects", g.FilterSysProjects, "filter", g.Filter)
	listReq := g.resourceManagerService.Projects.List()
	if g.Filter != "" {
		listReq = listReq.Filter(g.Filter)
	}
	err := listReq.Pages(context.Background(), func(page *cloudresourcemanager.ListProjectsResponse) error {
		for _, project := range page.Projects {
			if g.FilterSysProjects && g.isSysProject(project) {
				slog.Debug("Skipping system project", "projectId", project.ProjectId, "name", project.Name)
				continue
			}
			gcpProject := &tab.CloudResource{
				Name:         project.ProjectId,
				DisplayName:  project.Name,
				Provider:     "gcp",
				ResourceType: "gcp_project",
				Region:       "global",
				AccountRef:   project.ProjectId,
				Properties: map[string]any{
					"projectId":      project.ProjectId,
					"name":           project.Name,
					"projectNumber":  project.ProjectNumber,
					"lifecycleState": project.LifecycleState,
					"createTime":     project.CreateTime,
					"parent":         project.Parent,
					"labels":         project.Labels,
				},
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
