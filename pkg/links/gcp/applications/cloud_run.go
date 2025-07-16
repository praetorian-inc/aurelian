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
// GcpCloudRunServiceInfoLink
// GcpCloudRunServiceListLink

// get information about a specific Cloud Run service
type GcpCloudRunServiceInfoLink struct {
	*base.GcpBaseLink
	runService *run.APIService
	ProjectId  string
	Region     string
}

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
	// Get the specific Cloud Run service
	name := fmt.Sprintf("projects/%s/locations/%s/services/%s", g.ProjectId, g.Region, serviceName)
	service, err := g.runService.Projects.Locations.Services.Get(name).Do()
	if err != nil {
		return fmt.Errorf("failed to get Cloud Run service %s: %w", serviceName, err)
	}

	properties := g.postProcessSingle(service)
	gcpCloudRunService, err := tab.NewGCPResource(
		service.Metadata.Name,          // resource name
		g.ProjectId,                    // accountRef (project ID)
		tab.GCPResourceCloudRunService, // resource type
		properties,                     // properties
	)
	if err != nil {
		return fmt.Errorf("failed to create GCP Cloud Run service resource: %w", err)
	}
	g.Send(gcpCloudRunService)
	return nil
}

func (g *GcpCloudRunServiceInfoLink) postProcessSingle(service *run.Service) map[string]any {
	properties := map[string]any{
		"name":            service.Metadata.Name,
		"namespace":       service.Metadata.Namespace,
		"labels":          service.Metadata.Labels,
		"annotations":     service.Metadata.Annotations,
		"generation":      service.Metadata.Generation,
		"creationTime":    service.Metadata.CreationTimestamp,
		"selfLink":        service.Metadata.SelfLink,
		"uid":             service.Metadata.Uid,
		"resourceVersion": service.Metadata.ResourceVersion,
	}

	// Extract public URL from service status
	if service.Status != nil && service.Status.Url != "" {
		properties["publicURL"] = service.Status.Url
	}

	// Extract detailed service spec information
	if service.Spec != nil {
		properties["spec"] = service.Spec
		if service.Spec.Template != nil {
			properties["template"] = service.Spec.Template
			if service.Spec.Template.Spec != nil {
				properties["containerConcurrency"] = service.Spec.Template.Spec.ContainerConcurrency
				properties["timeoutSeconds"] = service.Spec.Template.Spec.TimeoutSeconds
				properties["serviceAccountName"] = service.Spec.Template.Spec.ServiceAccountName

				// Extract container information
				if len(service.Spec.Template.Spec.Containers) > 0 {
					container := service.Spec.Template.Spec.Containers[0]
					properties["image"] = container.Image
					properties["ports"] = container.Ports
					properties["env"] = container.Env
					properties["resources"] = container.Resources
					properties["command"] = container.Command
					properties["args"] = container.Args
					properties["workingDir"] = container.WorkingDir
				}
			}
		}
	}

	// Extract detailed status information
	if service.Status != nil {
		properties["status"] = service.Status
		properties["observedGeneration"] = service.Status.ObservedGeneration
		properties["conditions"] = service.Status.Conditions

		// Extract traffic allocation information
		if len(service.Status.Traffic) > 0 {
			var trafficInfo []map[string]any
			for _, traffic := range service.Status.Traffic {
				trafficInfo = append(trafficInfo, map[string]any{
					"revisionName":   traffic.RevisionName,
					"percent":        traffic.Percent,
					"url":            traffic.Url,
					"tag":            traffic.Tag,
					"latestRevision": traffic.LatestRevision,
				})
			}
			properties["traffic"] = trafficInfo
		}
	}

	return properties
}

// list Cloud Run services within a project
type GcpCloudRunServiceListLink struct {
	*base.GcpBaseLink
	runService *run.APIService
}

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

	// List locations that support Cloud Run
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

			// List services in this location
			parent := fmt.Sprintf("projects/%s/locations/%s", projectId, locationId)
			servicesCall := g.runService.Projects.Locations.Services.List(parent)
			servicesResp, err := servicesCall.Do()
			if err == nil && servicesResp != nil {
				for _, service := range servicesResp.Items {
					properties := g.postProcess(service)
					gcpCloudRunService, err := tab.NewGCPResource(
						service.Metadata.Name,          // resource name
						projectId,                      // accountRef (project ID)
						tab.GCPResourceCloudRunService, // resource type
						properties,                     // properties
					)
					if err != nil {
						slog.Error("Failed to create GCP Cloud Run service resource", "error", err, "service", service.Metadata.Name)
						continue
					}
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

func (g *GcpCloudRunServiceListLink) postProcess(service *run.Service) map[string]any {
	properties := map[string]any{
		"name":         service.Metadata.Name,
		"namespace":    service.Metadata.Namespace,
		"labels":       service.Metadata.Labels,
		"annotations":  service.Metadata.Annotations,
		"generation":   service.Metadata.Generation,
		"creationTime": service.Metadata.CreationTimestamp,
		"selfLink":     service.Metadata.SelfLink,
	}

	// Extract public URL from service status
	if service.Status != nil && service.Status.Url != "" {
		properties["publicURL"] = service.Status.Url
	}

	// Extract additional service details
	if service.Spec != nil && service.Spec.Template != nil {
		properties["image"] = ""
		if service.Spec.Template.Spec != nil && len(service.Spec.Template.Spec.Containers) > 0 {
			properties["image"] = service.Spec.Template.Spec.Containers[0].Image
		}
	}

	// Extract traffic allocation information
	if service.Status != nil && len(service.Status.Traffic) > 0 {
		var trafficInfo []map[string]any
		for _, traffic := range service.Status.Traffic {
			trafficInfo = append(trafficInfo, map[string]any{
				"revisionName": traffic.RevisionName,
				"percent":      traffic.Percent,
				"url":          traffic.Url,
			})
		}
		properties["traffic"] = trafficInfo
	}

	return properties
}
