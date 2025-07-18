package compute

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"sync"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/utils"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/compute/v1"
)

// FILE INFO:
// GcpInstanceInfoLink - get info of a single compute instance, Process(instanceName string); needs project and zone
// GcpInstanceListLink - list all compute instances in a project, Process(resource tab.GCPResource)

type GcpInstanceInfoLink struct {
	*base.GcpBaseLink
	computeService *compute.Service
	ProjectId      string
	Zone           string
}

// creates a link to get info of a single compute instance
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
	gcpInstance, err := tab.NewGCPResource(
		strconv.FormatUint(instance.Id, 10),      // resource name
		g.ProjectId,                              // accountRef (project ID)
		tab.GCPResourceInstance,                  // resource type
		linkPostProcessComputeInstance(instance), // properties
	)
	if err != nil {
		return fmt.Errorf("failed to create GCP instance resource: %w", err)
	}
	gcpInstance.DisplayName = instance.Name
	g.Send(gcpInstance)
	return nil
}

type GcpInstanceListLink struct {
	*base.GcpBaseLink
	computeService *compute.Service
}

// creates a link to list all compute instances in a project
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
	return utils.HandleGcpError(err, "failed to create compute service")
}

func (g *GcpInstanceListLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceProject {
		return nil
	}
	projectId := resource.Name
	zonesListCall := g.computeService.Zones.List(projectId)
	zonesResp, err := zonesListCall.Do()
	if err != nil {
		return utils.HandleGcpError(err, "failed to list zones in project")
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
					gcpInstance, err := tab.NewGCPResource(
						strconv.FormatUint(instance.Id, 10),      // resource name
						projectId,                                // accountRef (project ID)
						tab.GCPResourceInstance,                  // resource type
						linkPostProcessComputeInstance(instance), // properties
					)
					if err != nil {
						slog.Error("Failed to create GCP instance resource", "error", err, "instance", instance.Name)
						continue
					}
					gcpInstance.DisplayName = instance.Name
					g.Send(gcpInstance)
				}
				return nil
			})
			if handledErr := utils.HandleGcpError(err, "failed to list instances in zone"); handledErr != nil {
				slog.Error("error", "error", handledErr, "zone", zoneName)
			}
		}(zone.Name)
	}
	wg.Wait()
	return nil
}

// ------------------------------------------------------------------------------------------------
// helper functions

func linkPostProcessComputeInstance(instance *compute.Instance) map[string]any {
	properties := map[string]any{
		"name":        instance.Name,
		"id":          instance.Id,
		"description": instance.Description,
		"status":      instance.Status,
		"zone":        instance.Zone,
		"labels":      instance.Labels,
		"selfLink":    instance.SelfLink,
	}
	for _, networkInterface := range instance.NetworkInterfaces {
		for _, accessConfig := range networkInterface.AccessConfigs {
			if accessConfig.NatIP != "" {
				if utils.IsIPv4(accessConfig.NatIP) {
					properties["publicIP"] = accessConfig.NatIP
				}
			}
			if accessConfig.PublicPtrDomainName != "" {
				properties["publicDomain"] = accessConfig.PublicPtrDomainName
			}
		}
		for _, ipv6AccessConfig := range networkInterface.Ipv6AccessConfigs {
			if ipv6AccessConfig.ExternalIpv6 != "" {
				if utils.IsIPv6(ipv6AccessConfig.ExternalIpv6) {
					properties["publicIPv6"] = ipv6AccessConfig.ExternalIpv6
				}
			}
		}
	}
	return properties
}
