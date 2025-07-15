package compute

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/dns/v1"
)

// NOTE: placing zones and dns in the same package though they're technically outside compute scope
// temporarily clubbing as networking

// FILE INFO:
// GcpGlobalForwardingRuleListLink
// GcpRegionalForwardingRuleListLink
// GcpDnsManagedZoneListLink
// NetworkingMultiChain

// ------------------------------------------------------------------------------------------------

// list global forwarding rules within a project
type GcpGlobalForwardingRuleListLink struct {
	*base.GcpBaseLink
	computeService *compute.Service
}

func NewGcpGlobalForwardingRuleListLink(configs ...cfg.Config) chain.Link {
	g := &GcpGlobalForwardingRuleListLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpGlobalForwardingRuleListLink) Initialize() error {
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

func (g *GcpGlobalForwardingRuleListLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceProject {
		return nil
	}
	projectId := resource.Name
	globalListReq := g.computeService.GlobalForwardingRules.List(projectId)
	err := globalListReq.Pages(context.Background(), func(page *compute.ForwardingRuleList) error {
		for _, rule := range page.Items {
			properties := map[string]any{
				"name":                rule.Name,
				"id":                  rule.Id,
				"description":         rule.Description,
				"region":              rule.Region,
				"ipAddress":           rule.IPAddress,
				"ipProtocol":          rule.IPProtocol,
				"portRange":           rule.PortRange,
				"ports":               rule.Ports,
				"target":              rule.Target,
				"backendService":      rule.BackendService,
				"loadBalancingScheme": rule.LoadBalancingScheme,
				"network":             rule.Network,
				"subnetwork":          rule.Subnetwork,
				"networkTier":         rule.NetworkTier,
				"labels":              rule.Labels,
				"creationTimestamp":   rule.CreationTimestamp,
				"selfLink":            rule.SelfLink,
			}
			gcpForwardingRule, err := tab.NewGCPResource(
				rule.Name,                           // resource name
				projectId,                           // accountRef (project ID)
				tab.GCPResourceGlobalForwardingRule, // resource type
				properties,                          // properties
			)
			if err != nil {
				slog.Error("Failed to create GCP global forwarding rule resource", "error", err, "rule", rule.Name)
				continue
			}
			g.Send(gcpForwardingRule)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to list global forwarding rules: %w", err)
	}
	return nil
}

// list regional forwarding rules within a project
type GcpRegionalForwardingRuleListLink struct {
	*base.GcpBaseLink
	computeService *compute.Service
}

func NewGcpRegionalForwardingRuleListLink(configs ...cfg.Config) chain.Link {
	g := &GcpRegionalForwardingRuleListLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpRegionalForwardingRuleListLink) Initialize() error {
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

func (g *GcpRegionalForwardingRuleListLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceProject {
		return nil
	}
	projectId := resource.Name
	regionsListCall := g.computeService.Regions.List(projectId)
	regionsResp, err := regionsListCall.Do()
	if err != nil {
		return fmt.Errorf("failed to list regions in project %s: %w", projectId, err)
	}
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	for _, region := range regionsResp.Items {
		wg.Add(1)
		sem <- struct{}{}
		go func(regionName string) {
			defer wg.Done()
			defer func() { <-sem }()
			regionalListReq := g.computeService.ForwardingRules.List(projectId, regionName)
			err := regionalListReq.Pages(context.Background(), func(page *compute.ForwardingRuleList) error {
				for _, rule := range page.Items {
					properties := map[string]any{
						"name":                rule.Name,
						"id":                  rule.Id,
						"description":         rule.Description,
						"region":              rule.Region,
						"ipAddress":           rule.IPAddress,
						"ipProtocol":          rule.IPProtocol,
						"portRange":           rule.PortRange,
						"ports":               rule.Ports,
						"target":              rule.Target,
						"backendService":      rule.BackendService,
						"loadBalancingScheme": rule.LoadBalancingScheme,
						"network":             rule.Network,
						"subnetwork":          rule.Subnetwork,
						"networkTier":         rule.NetworkTier,
						"labels":              rule.Labels,
						"creationTimestamp":   rule.CreationTimestamp,
						"selfLink":            rule.SelfLink,
					}
					gcpForwardingRule, err := tab.NewGCPResource(
						rule.Name,                     // resource name
						projectId,                     // accountRef (project ID)
						tab.GCPResourceForwardingRule, // resource type
						properties,                    // properties
					)
					if err != nil {
						slog.Error("Failed to create GCP regional forwarding rule resource", "error", err, "rule", rule.Name)
						continue
					}
					g.Send(gcpForwardingRule)
				}
				return nil
			})
			if err != nil {
				slog.Error("Failed to list forwarding rules in region", "error", err, "region", regionName)
			}
		}(region.Name)
	}
	wg.Wait()
	return nil
}

// list DNS managed zones within a project
type GcpDnsManagedZoneListLink struct {
	*base.GcpBaseLink
	dnsService *dns.Service
}

func NewGcpDnsManagedZoneListLink(configs ...cfg.Config) chain.Link {
	g := &GcpDnsManagedZoneListLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpDnsManagedZoneListLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.dnsService, err = dns.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create dns service: %w", err)
	}
	return nil
}

func (g *GcpDnsManagedZoneListLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceProject {
		return nil
	}
	projectId := resource.Name
	listReq := g.dnsService.ManagedZones.List(projectId)
	err := listReq.Pages(context.Background(), func(page *dns.ManagedZonesListResponse) error {
		for _, zone := range page.ManagedZones {
			properties := map[string]any{
				"name":                    zone.Name,
				"id":                      zone.Id,
				"dnsName":                 zone.DnsName,
				"description":             zone.Description,
				"nameServers":             zone.NameServers,
				"visibility":              zone.Visibility,
				"creationTime":            zone.CreationTime,
				"labels":                  zone.Labels,
				"nameServerSet":           zone.NameServerSet,
				"dnssecConfig":            zone.DnssecConfig,
				"privateVisibilityConfig": zone.PrivateVisibilityConfig,
				"forwardingConfig":        zone.ForwardingConfig,
				"peeringConfig":           zone.PeeringConfig,
				"reverseLookupConfig":     zone.ReverseLookupConfig,
				"serviceDirectoryConfig":  zone.ServiceDirectoryConfig,
			}
			gcpDnsZone, err := tab.NewGCPResource(
				zone.Name,                     // resource name
				projectId,                     // accountRef (project ID)
				tab.GCPResourceDnsManagedZone, // resource type
				properties,                    // properties
			)
			if err != nil {
				slog.Error("Failed to create GCP DNS managed zone resource", "error", err, "zone", zone.Name)
				continue
			}
			g.Send(gcpDnsZone)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to list DNS managed zones: %w", err)
	}
	return nil
}

// networking fan out link
type GCPNetworkingFanOut struct {
	*base.GcpBaseLink
}

func NewGCPNetworkingFanOut(configs ...cfg.Config) chain.Link {
	g := &GCPNetworkingFanOut{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GCPNetworkingFanOut) Process(project tab.GCPResource) error {
	if project.ResourceType != tab.GCPResourceProject {
		return nil
	}
	multi := chain.NewMulti(
		chain.NewChain(NewGcpGlobalForwardingRuleListLink()),
		chain.NewChain(NewGcpRegionalForwardingRuleListLink()),
		chain.NewChain(NewGcpDnsManagedZoneListLink()),
	)
	multi.WithConfigs(cfg.WithArgs(g.Args()))
	multi.Send(project)
	multi.Close()
	for result, ok := chain.RecvAs[*tab.GCPResource](multi); ok; result, ok = chain.RecvAs[*tab.GCPResource](multi) {
		g.Send(result)
	}
	err := multi.Error()
	if err != nil {
		slog.Error("Error in GCP networking fan out", "error", err)
	}
	return nil
}
