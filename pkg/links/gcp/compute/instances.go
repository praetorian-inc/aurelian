package compute

import (
	"context"
	"fmt"
	"log/slog"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	jtypes "github.com/praetorian-inc/janus-framework/pkg/types"
	"github.com/praetorian-inc/diocletian/pkg/links/gcp/base"
	"github.com/praetorian-inc/diocletian/pkg/links/options"
	"github.com/praetorian-inc/diocletian/pkg/output"
	"github.com/praetorian-inc/diocletian/pkg/utils"
	"google.golang.org/api/compute/v1"
)

// FILE INFO:
// GcpInstanceInfoLink - get info of a single compute instance, Process(instanceName string); needs project and zone
// GcpInstanceListLink - list all compute instances in a project, Process(resource output.CloudResource)
// GcpInstanceSecretsLink - extract secrets from a compute instance, Process(input output.CloudResource)

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
	gcpInstance := &output.CloudResource{
		Platform:     "gcp",
		ResourceType: "compute.googleapis.com/Instance",
		ResourceID:   fmt.Sprintf("projects/%s/zones/%s/instances/%s", g.ProjectId, g.Zone, strconv.FormatUint(instance.Id, 10)),
		AccountRef:   g.ProjectId,
		Region:       g.Zone,
		DisplayName:  instance.Name,
		Properties:   linkPostProcessComputeInstance(instance),
	}
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

func (g *GcpInstanceListLink) Process(resource output.CloudResource) error {
	if resource.ResourceType != "cloudresourcemanager.googleapis.com/Project" {
		return nil
	}
	projectId := resource.AccountRef
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
					gcpInstance := &output.CloudResource{
						Platform:     "gcp",
						ResourceType: "compute.googleapis.com/Instance",
						ResourceID:   fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectId, zoneName, strconv.FormatUint(instance.Id, 10)),
						AccountRef:   projectId,
						Region:       zoneName,
						DisplayName:  instance.Name,
						Properties:   linkPostProcessComputeInstance(instance),
					}
					slog.Debug("Sending GCP instance", "instance", gcpInstance.DisplayName)
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

type GcpInstanceSecretsLink struct {
	*base.GcpBaseLink
	computeService *compute.Service
}

// creates a link to scan compute instance for secrets
func NewGcpInstanceSecretsLink(configs ...cfg.Config) chain.Link {
	g := &GcpInstanceSecretsLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpInstanceSecretsLink) Initialize() error {
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

func (g *GcpInstanceSecretsLink) Process(input output.CloudResource) error {
	if input.ResourceType != "compute.googleapis.com/Instance" {
		return nil
	}
	projectId := input.AccountRef
	instanceName := input.DisplayName
	zoneURL, _ := input.Properties["zone"].(string)
	zone := path.Base(zoneURL)
	if projectId == "" || zone == "" || instanceName == "" {
		return nil
	}
	inst, err := g.computeService.Instances.Get(projectId, zone, instanceName).Do()
	if err != nil {
		return utils.HandleGcpError(err, "failed to get instance for secrets extraction")
	}
	var metadataContent strings.Builder
	if inst.Metadata != nil {
		for _, item := range inst.Metadata.Items {
			if item == nil || item.Value == nil || *item.Value == "" {
				continue
			}
			metadataContent.WriteString(fmt.Sprintf("GCP Instance Metadata: %s\n", item.Key))
			metadataContent.WriteString(*item.Value)
			metadataContent.WriteString("\n\n")
		}
	}
	if metadataContent.Len() > 0 {
		g.Send(jtypes.NPInput{
			Content: metadataContent.String(),
			Provenance: jtypes.NPProvenance{
				Platform:     "gcp",
				ResourceType: "compute.googleapis.com/Instance::Metadata",
				ResourceID:   input.ResourceID,
				Region:       zone,
				AccountID:    projectId,
			},
		})
	}
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
