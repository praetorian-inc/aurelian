package compute

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
	"google.golang.org/api/compute/v1"
)

// FILE INFO:
// GcpInstanceInfoLink
// GcpInstanceListLink

// get information about a compute instance
type GcpInstanceInfoLink struct {
	*base.GcpBaseLink
	computeService *compute.Service
	ProjectId      string
	Zone           string
}

func NewGcpInstanceInfoLink(configs ...cfg.Config) chain.Link {
	g := &GcpInstanceInfoLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpInstanceInfoLink) Params() []cfg.Param {
	params := append(g.GcpBaseLink.Params(),
		options.GcpProject(),
		options.GcpZone(),
	)
	return params
}

func (g *GcpInstanceInfoLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.computeService, err = compute.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create compute service: %w", err)
	}
	projectId, err := cfg.As[string](g.Arg("project"))
	if err != nil {
		return fmt.Errorf("failed to get project: %w", err)
	}
	g.ProjectId = projectId
	zone, err := cfg.As[string](g.Arg("zone"))
	if err != nil {
		return fmt.Errorf("failed to get zone: %w", err)
	}
	g.Zone = zone
	return nil
}

func (g *GcpInstanceInfoLink) Process(instanceName string) error {
	instance, err := g.computeService.Instances.Get(g.ProjectId, g.Zone, instanceName).Do()
	if err != nil {
		return fmt.Errorf("failed to get instance %s: %w", instanceName, err)
	}
	properties := map[string]any{
		"name":              instance.Name,
		"id":                instance.Id,
		"description":       instance.Description,
		"status":            instance.Status,
		"zone":              instance.Zone,
		"machineType":       instance.MachineType,
		"canIpForward":      instance.CanIpForward,
		"networkInterfaces": instance.NetworkInterfaces,
		"disks":             instance.Disks,
		"metadata":          instance.Metadata,
		"tags":              instance.Tags,
		"labels":            instance.Labels,
		"creationTimestamp": instance.CreationTimestamp,
		"selfLink":          instance.SelfLink,
		// "publicIp":          g.getPublicIp(instance),
	}
	gcpInstance, err := tab.NewGCPResource(
		instance.Name,           // resource name
		g.ProjectId,             // accountRef (project ID)
		tab.GCPResourceInstance, // resource type
		properties,              // properties
	)
	if err != nil {
		return fmt.Errorf("failed to create GCP instance resource: %w", err)
	}
	g.Send(gcpInstance)
	return nil
}

// list instances within a project
type GcpInstanceListLink struct {
	*base.GcpBaseLink
	computeService *compute.Service
}

func NewGcpInstanceListLink(configs ...cfg.Config) chain.Link {
	g := &GcpInstanceListLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpInstanceListLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.computeService, err = compute.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create compute service: %w", err)
	}
	return nil
}

func (g *GcpInstanceListLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceProject {
		return nil
	}
	projectId := resource.Name
	zonesListCall := g.computeService.Zones.List(projectId)
	zonesResp, err := zonesListCall.Do()
	if err != nil {
		return fmt.Errorf("failed to list zones in project %s: %w", projectId, err)
	}
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	for _, zone := range zonesResp.Items {
		wg.Add(1)
		sem <- struct{}{}
		go func(zoneName string) {
			defer wg.Done()
			defer func() { <-sem }()

			listReq := g.computeService.Instances.List(projectId, zoneName)
			err := listReq.Pages(context.Background(), func(page *compute.InstanceList) error {
				for _, instance := range page.Items {
					properties := map[string]any{
						"name":              instance.Name,
						"id":                instance.Id,
						"description":       instance.Description,
						"status":            instance.Status,
						"zone":              instance.Zone,
						"machineType":       instance.MachineType,
						"canIpForward":      instance.CanIpForward,
						"networkInterfaces": instance.NetworkInterfaces,
						"disks":             instance.Disks,
						"metadata":          instance.Metadata,
						"tags":              instance.Tags,
						"labels":            instance.Labels,
						"creationTimestamp": instance.CreationTimestamp,
						"selfLink":          instance.SelfLink,
					}
					gcpInstance, err := tab.NewGCPResource(
						instance.Name,           // resource name
						projectId,               // accountRef (project ID)
						tab.GCPResourceInstance, // resource type
						properties,              // properties
					)
					if err != nil {
						slog.Error("Failed to create GCP instance resource", "error", err, "instance", instance.Name)
						continue
					}
					g.Send(gcpInstance)
				}
				return nil
			})
			if err != nil {
				slog.Error("Failed to list instances in zone", "error", err, "zone", zoneName)
			}
		}(zone.Name)
	}
	wg.Wait()
	return nil
}
