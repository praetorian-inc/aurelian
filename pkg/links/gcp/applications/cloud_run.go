package applications

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/utils"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/run/v2"
)

// FILE INFO:
// GcpCloudRunServiceInfoLink - get info of a single Cloud Run service, Process(serviceName string); needs project and region
// GcpCloudRunServiceListLink - list all Cloud Run services in a project, Process(resource tab.GCPResource)

type GcpCloudRunServiceInfoLink struct {
	*base.GcpBaseLink
	runService *run.Service
	ProjectId  string
	Region     string
}

// creates a link to get info of a single Cloud Run service
func NewGcpCloudRunServiceInfoLink(configs ...cfg.Config) chain.Link {
	g := &GcpCloudRunServiceInfoLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpCloudRunServiceInfoLink) Params() []cfg.Param {
	params := append(g.GcpBaseLink.Params(),
		options.GcpProject(),
		options.GcpRegion(),
	)
	return params
}

func (g *GcpCloudRunServiceInfoLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.runService, err = run.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create cloud run service: %w", err)
	}
	projectId, err := cfg.As[string](g.Arg("project"))
	if err != nil {
		return fmt.Errorf("failed to get project: %w", err)
	}
	g.ProjectId = projectId
	region, err := cfg.As[string](g.Arg("region"))
	if err != nil {
		return fmt.Errorf("failed to get region: %w", err)
	}
	g.Region = region
	return nil
}

func (g *GcpCloudRunServiceInfoLink) Process(serviceName string) error {
	name := fmt.Sprintf("projects/%s/locations/%s/services/%s", g.ProjectId, g.Region, serviceName)
	service, err := g.runService.Projects.Locations.Services.Get(name).Do()
	if err != nil {
		return utils.HandleGcpError(err, "failed to get Cloud Run service")
	}
	gcpCloudRunService, err := tab.NewGCPResource(
		service.Name,                            // resource name
		g.ProjectId,                             // accountRef (project ID)
		tab.GCPResourceCloudRunService,          // resource type
		linkPostProcessCloudRunService(service), // properties
	)
	if err != nil {
		return fmt.Errorf("failed to create GCP Cloud Run service resource: %w", err)
	}
	gcpCloudRunService.DisplayName = gcpCloudRunService.Name
	g.Send(gcpCloudRunService)
	return nil
}

type GcpCloudRunServiceListLink struct {
	*base.GcpBaseLink
	runService    *run.Service
	regionService *compute.Service
}

// creates a link to list all Cloud Run services in a project
func NewGcpCloudRunServiceListLink(configs ...cfg.Config) chain.Link {
	g := &GcpCloudRunServiceListLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpCloudRunServiceListLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.runService, err = run.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create cloud run service: %w", err)
	}
	g.regionService, err = compute.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create compute service: %w", err)
	}
	return nil
}

func (g *GcpCloudRunServiceListLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceProject {
		return nil
	}
	projectId := resource.Name
	regionsCall := g.regionService.Regions.List(projectId)
	regionsResp, err := regionsCall.Do()
	if err != nil {
		return utils.HandleGcpError(err, "failed to list regions in project")
	}
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	for _, region := range regionsResp.Items {
		wg.Add(1)
		sem <- struct{}{}
		go func(regionId string) {
			defer wg.Done()
			defer func() { <-sem }()
			parent := fmt.Sprintf("projects/%s/locations/%s", projectId, regionId)
			servicesCall := g.runService.Projects.Locations.Services.List(parent)
			servicesResp, err := servicesCall.Do()
			if err == nil && servicesResp != nil {
				for _, service := range servicesResp.Services {
					gcpCloudRunService, err := tab.NewGCPResource(
						service.Name,                            // resource name
						projectId,                               // accountRef (project ID)
						tab.GCPResourceCloudRunService,          // resource type
						linkPostProcessCloudRunService(service), // properties
					)
					if err != nil {
						slog.Error("Failed to create GCP Cloud Run service resource", "error", err, "service", service.Name)
						continue
					}
					gcpCloudRunService.DisplayName = gcpCloudRunService.Name
					g.Send(gcpCloudRunService)
				}
			} else if err != nil {
				slog.Error("Failed to list Cloud Run services in region", "error", err, "region", regionId)
			}
		}(region.Name)
	}
	wg.Wait()
	return nil
}

// ------------------------------------------------------------------------------------------------
// helper functions

func linkPostProcessCloudRunService(service *run.GoogleCloudRunV2Service) map[string]any {
	properties := map[string]any{
		"name":      service.Name,
		"namespace": service.Annotations["cloud.googleapis.com/namespace"],
		"labels":    service.Labels,
	}
	properties["uid"] = service.Annotations["cloud.googleapis.com/uid"]
	properties["publicURLs"] = service.Urls
	if service.Template != nil {
		properties["serviceAccountName"] = service.Template.ServiceAccount
		if len(service.Template.Containers) > 0 {
			container := service.Template.Containers[0]
			properties["image"] = container.Image
			properties["command"] = container.Command
			properties["args"] = container.Args
			properties["workingDir"] = container.WorkingDir
		}
	}
	return properties
}
