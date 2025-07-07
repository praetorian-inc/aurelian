package compute

import (
	"context"
	"fmt"
	"log/slog"
	"path"
	"sync"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/compute/v1"
)

type GcpComputeInstanceLister struct {
	*base.GcpReconLink
	computeService *compute.Service
	wg             sync.WaitGroup
	semaphores     map[string]chan struct{}
}

func NewGcpComputeInstanceLister(configs ...cfg.Config) chain.Link {
	g := &GcpComputeInstanceLister{}
	g.GcpReconLink = base.NewGcpReconLink(g, configs...)
	return g
}

func (g *GcpComputeInstanceLister) Initialize() error {
	if err := g.GcpReconLink.Initialize(); err != nil {
		return err
	}

	var err error
	g.computeService, err = compute.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create compute service: %w", err)
	}

	g.initializeSemaphores()
	return nil
}

func (g *GcpComputeInstanceLister) initializeSemaphores() {
	g.semaphores = make(map[string]chan struct{})
	for _, project := range g.Projects {
		g.semaphores[project] = make(chan struct{}, 5)
	}
}

func (g *GcpComputeInstanceLister) Process(project string) error {
	regionsToList := g.Regions

	// If "all" regions, loop
	if len(regionsToList) == 1 && regionsToList[0] == "all" {
		regions, err := g.discoverRegions(project)
		if err != nil {
			return fmt.Errorf("failed to discover regions for project %s: %w", project, err)
		}
		regionsToList = regions
	}

	for _, region := range regionsToList {
		g.wg.Add(1)
		go g.listInstancesInRegion(project, region)
	}

	g.wg.Wait()
	slog.Debug("Completed listing instances", "project", project)
	return nil
}

func (g *GcpComputeInstanceLister) discoverRegions(project string) ([]string, error) {
	regionList, err := g.computeService.Regions.List(project).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list regions: %w", err)
	}

	regions := make([]string, 0, len(regionList.Items))
	for _, region := range regionList.Items {
		regions = append(regions, region.Name)
	}

	slog.Debug("Discovered regions", "project", project, "count", len(regions), "regions", regions)
	return regions, nil
}

func (g *GcpComputeInstanceLister) listInstancesInRegion(project, region string) {
	defer g.wg.Done()

	slog.Debug("Listing instances in region", "project", project, "region", region)

	sem := g.semaphores[project]
	sem <- struct{}{}
	defer func() { <-sem }()

	regionDetails, err := g.computeService.Regions.Get(project, region).Do()
	if err != nil {
		slog.Error("Failed to get region details", "error", err, "project", project, "region", region)
		return
	}

	for _, zoneURL := range regionDetails.Zones {
		zoneName := path.Base(zoneURL)
		if err := g.listInstancesInZone(project, region, zoneName); err != nil {
			slog.Error("Failed to list instances in zone", "error", err, "project", project, "zone", zoneName)
		}
	}
}

func (g *GcpComputeInstanceLister) listInstancesInZone(project, region, zone string) error {
	req := g.computeService.Instances.List(project, zone)

	return req.Pages(context.Background(), func(page *compute.InstanceList) error {
		for _, instance := range page.Items {
			gcpInstance := &tab.CloudResource{
				Name:         instance.Name,
				DisplayName:  instance.Name,
				Provider:     "gcp",
				ResourceType: tab.GCPResourceInstance,
				Region:       region,
				AccountRef:   project,
				Properties: map[string]any{
					"zone":              zone,
					"machineType":       path.Base(instance.MachineType),
					"status":            instance.Status,
					"selfLink":          instance.SelfLink,
					"creationTimestamp": instance.CreationTimestamp,
					"id":                instance.Id,
					"networkInterfaces": instance.NetworkInterfaces,
					"disks":             instance.Disks,
					"metadata":          instance.Metadata,
					"tags":              instance.Tags,
					"serviceAccounts":   instance.ServiceAccounts,
				},
			}

			slog.Debug("Found instance", "project", project, "zone", zone, "instance", instance.Name, "status", instance.Status)
			g.Send(gcpInstance)
		}
		return nil
	})
}

func (g *GcpComputeInstanceLister) Complete() error {
	g.wg.Wait()
	return nil
}
