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
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/run/v1"
)

// FILE INFO:
// GcpCloudRunServiceInfoLink - get info of a single Cloud Run service, Process(serviceName string); needs project and region
// GcpCloudRunServiceListLink - list all Cloud Run services in a project, Process(resource tab.GCPResource)

type GcpCloudRunServiceInfoLink struct {
	*base.GcpBaseLink
	runService *run.APIService
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
		return fmt.Errorf("failed to get Cloud Run service %s: %w", serviceName, err)
	}
	gcpCloudRunService, err := tab.NewGCPResource(
		service.Metadata.Name,                   // resource name
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
	runService *run.APIService
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
	return nil
}

func (g *GcpCloudRunServiceListLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceProject {
		return nil
	}
	projectId := resource.Name
	locationsCall := g.runService.Projects.Locations.List(fmt.Sprintf("projects/%s", projectId))
	locationsResp, err := locationsCall.Do()
	if err != nil {
		return fmt.Errorf("failed to list locations in project %s: %w", projectId, err)
	}
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	for _, location := range locationsResp.Locations {
		wg.Add(1)
		sem <- struct{}{}
		go func(locationId string) {
			defer wg.Done()
			defer func() { <-sem }()
			parent := fmt.Sprintf("projects/%s/locations/%s", projectId, locationId)
			servicesCall := g.runService.Projects.Locations.Services.List(parent)
			servicesResp, err := servicesCall.Do()
			if err == nil && servicesResp != nil {
				for _, service := range servicesResp.Items {
					gcpCloudRunService, err := tab.NewGCPResource(
						service.Metadata.Name,                   // resource name
						projectId,                               // accountRef (project ID)
						tab.GCPResourceCloudRunService,          // resource type
						linkPostProcessCloudRunService(service), // properties
					)
					if err != nil {
						slog.Error("Failed to create GCP Cloud Run service resource", "error", err, "service", service.Metadata.Name)
						continue
					}
					gcpCloudRunService.DisplayName = gcpCloudRunService.Name
					g.Send(gcpCloudRunService)
				}
			}
			if err != nil {
				slog.Error("Failed to list Cloud Run services in location", "error", err, "location", locationId)
			}
		}(location.LocationId)
	}
	wg.Wait()
	return nil
}

// ------------------------------------------------------------------------------------------------
// helper functions

func linkPostProcessCloudRunService(service *run.Service) map[string]any {
	properties := map[string]any{
		"name":      service.Metadata.Name,
		"namespace": service.Metadata.Namespace,
		"labels":    service.Metadata.Labels,
		"selfLink":  service.Metadata.SelfLink,
	}
	properties["status"] = service.Status.Conditions
	properties["uid"] = service.Metadata.Uid
	if service.Status != nil && service.Status.Url != "" {
		properties["publicURL"] = service.Status.Url
	}
	if service.Spec != nil {
		if service.Spec.Template != nil {
			properties["template"] = service.Spec.Template
			if service.Spec.Template.Spec != nil {
				properties["serviceAccountName"] = service.Spec.Template.Spec.ServiceAccountName
				if len(service.Spec.Template.Spec.Containers) > 0 {
					container := service.Spec.Template.Spec.Containers[0]
					properties["image"] = container.Image
					// properties["ports"] = container.Ports
					// properties["env"] = container.Env
					properties["command"] = container.Command
					properties["args"] = container.Args
					properties["workingDir"] = container.WorkingDir
				}
			}
		}
	}
	return properties
}
