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
	"github.com/praetorian-inc/nebula/pkg/utils"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/dns/v1"
)

// NOTE: placing zones and dns in the same package though they're technically outside compute scope
// temporarily clubbing as networking

// FILE INFO:
// GcpGlobalForwardingRuleListLink - list all global forwarding rules in a project
// GcpRegionalForwardingRuleListLink - list all regional forwarding rules in a project
// GcpGlobalAddressListLink - list all global addresses in a project
// GcpRegionalAddressListLink - list all regional addresses in a project
// GcpDnsManagedZoneListLink - list all DNS managed zones in a project
// GCPNetworkingFanOut - fan out to all networking resources in a project

// ------------------------------------------------------------------------------------------------

type GcpGlobalForwardingRuleListLink struct {
	*base.GcpBaseLink
	computeService *compute.Service
}

// creates a link to list all global forwarding rules in a project
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
			properties := g.postProcess(rule)
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

func (g *GcpGlobalForwardingRuleListLink) postProcess(rule *compute.ForwardingRule) map[string]any {
	properties := map[string]any{
		"name":                rule.Name,
		"id":                  strconv.FormatUint(rule.Id, 10),
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
		"labels":              rule.Labels,
		"selfLink":            rule.SelfLink,
	}
	if rule.IPAddress != "" && (rule.LoadBalancingScheme == "EXTERNAL" || rule.LoadBalancingScheme == "EXTERNAL_MANAGED") {
		if utils.IsIPv4(rule.IPAddress) {
			properties["publicIP"] = rule.IPAddress
		} else if utils.IsIPv6(rule.IPAddress) {
			properties["publicIPv6"] = rule.IPAddress
		}
	}
	return properties
}

type GcpRegionalForwardingRuleListLink struct {
	*base.GcpBaseLink
	computeService *compute.Service
}

// creates a link to list all regional forwarding rules in a project
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
					gcpForwardingRule, err := tab.NewGCPResource(
						rule.Name,                     // resource name
						projectId,                     // accountRef (project ID)
						tab.GCPResourceForwardingRule, // resource type
						g.postProcess(rule),           // properties
					)
					if err != nil {
						slog.Error("Failed to create GCP regional forwarding rule resource", "error", err, "rule", rule.Name)
						continue
					}
					gcpForwardingRule.DisplayName = rule.Name
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

func (g *GcpRegionalForwardingRuleListLink) postProcess(rule *compute.ForwardingRule) map[string]any {
	properties := map[string]any{
		"name":                rule.Name,
		"id":                  strconv.FormatUint(rule.Id, 10),
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
		"labels":              rule.Labels,
		"selfLink":            rule.SelfLink,
	}
	if rule.IPAddress != "" && (rule.LoadBalancingScheme == "EXTERNAL" || rule.LoadBalancingScheme == "EXTERNAL_MANAGED") {
		if utils.IsIPv4(rule.IPAddress) {
			properties["publicIP"] = rule.IPAddress
		} else if utils.IsIPv6(rule.IPAddress) {
			properties["publicIPv6"] = rule.IPAddress
		}
	}
	return properties
}

type GcpGlobalAddressListLink struct {
	*base.GcpBaseLink
	computeService *compute.Service
}

// creates a link to list all global addresses in a project
func NewGcpGlobalAddressListLink(configs ...cfg.Config) chain.Link {
	g := &GcpGlobalAddressListLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpGlobalAddressListLink) Initialize() error {
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

func (g *GcpGlobalAddressListLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceProject {
		return nil
	}
	projectId := resource.Name
	globalListReq := g.computeService.GlobalAddresses.List(projectId)
	err := globalListReq.Pages(context.Background(), func(page *compute.AddressList) error {
		for _, address := range page.Items {
			gcpGlobalAddress, err := tab.NewGCPResource(
				address.Address,        // resource name
				projectId,              // accountRef (project ID)
				tab.GCPResourceAddress, // resource type
				g.postProcess(address), // properties
			)
			if err != nil {
				slog.Error("Failed to create GCP global address resource", "error", err, "address", address.Name)
				continue
			}
			gcpGlobalAddress.DisplayName = address.Name
			g.Send(gcpGlobalAddress)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to list global addresses: %w", err)
	}
	return nil
}

func (g *GcpGlobalAddressListLink) postProcess(address *compute.Address) map[string]any {
	properties := map[string]any{
		"name":         address.Name,
		"id":           strconv.FormatUint(address.Id, 10),
		"description":  address.Description,
		"region":       address.Region,
		"address":      address.Address,
		"status":       address.Status,
		"addressType":  address.AddressType,
		"purpose":      address.Purpose,
		"subnetwork":   address.Subnetwork,
		"network":      address.Network,
		"prefixLength": address.PrefixLength,
		"ipVersion":    address.IpVersion,
		"labels":       address.Labels,
		"selfLink":     address.SelfLink,
	}
	if address.Address != "" && address.AddressType == "EXTERNAL" {
		if utils.IsIPv4(address.Address) {
			properties["publicIP"] = address.Address
		} else if utils.IsIPv6(address.Address) {
			properties["publicIPv6"] = address.Address
		}
	}
	return properties
}

type GcpRegionalAddressListLink struct {
	*base.GcpBaseLink
	computeService *compute.Service
}

// creates a link to list all regional addresses in a project
func NewGcpRegionalAddressListLink(configs ...cfg.Config) chain.Link {
	g := &GcpRegionalAddressListLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpRegionalAddressListLink) Initialize() error {
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

func (g *GcpRegionalAddressListLink) Process(resource tab.GCPResource) error {
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
			regionalListReq := g.computeService.Addresses.List(projectId, regionName)
			err := regionalListReq.Pages(context.Background(), func(page *compute.AddressList) error {
				for _, address := range page.Items {
					gcpRegionalAddress, err := tab.NewGCPResource(
						address.Address,        // resource name
						projectId,              // accountRef (project ID)
						tab.GCPResourceAddress, // resource type
						g.postProcess(address), // properties
					)
					if err != nil {
						slog.Error("Failed to create GCP regional address resource", "error", err, "address", address.Name)
						continue
					}
					gcpRegionalAddress.DisplayName = address.Name
					g.Send(gcpRegionalAddress)
				}
				return nil
			})
			if err != nil {
				slog.Error("Failed to list addresses in region", "error", err, "region", regionName)
			}
		}(region.Name)
	}
	wg.Wait()
	return nil
}

func (g *GcpRegionalAddressListLink) postProcess(address *compute.Address) map[string]any {
	properties := map[string]any{
		"name":         address.Name,
		"id":           strconv.FormatUint(address.Id, 10),
		"description":  address.Description,
		"region":       address.Region,
		"address":      address.Address,
		"status":       address.Status,
		"addressType":  address.AddressType,
		"purpose":      address.Purpose,
		"subnetwork":   address.Subnetwork,
		"network":      address.Network,
		"prefixLength": address.PrefixLength,
		"ipVersion":    address.IpVersion,
		"labels":       address.Labels,
		"selfLink":     address.SelfLink,
	}
	if address.Address != "" && address.AddressType == "EXTERNAL" {
		if utils.IsIPv4(address.Address) {
			properties["publicIP"] = address.Address
		} else if utils.IsIPv6(address.Address) {
			properties["publicIPv6"] = address.Address
		}
	}
	return properties
}

type GcpDnsManagedZoneListLink struct {
	*base.GcpBaseLink
	dnsService *dns.Service
}

// creates a link to list all DNS managed zones in a project
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
			gcpDnsZone, err := tab.NewGCPResource(
				zone.Name,                     // resource name
				projectId,                     // accountRef (project ID)
				tab.GCPResourceDNSManagedZone, // resource type
				g.postProcess(zone),           // properties
			)
			if err != nil {
				slog.Error("Failed to create GCP DNS managed zone resource", "error", err, "zone", zone.Name)
				continue
			}
			gcpDnsZone.DisplayName = zone.DnsName
			g.Send(gcpDnsZone)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to list DNS managed zones: %w", err)
	}
	return nil
}

func (g *GcpDnsManagedZoneListLink) postProcess(zone *dns.ManagedZone) map[string]any {
	properties := map[string]any{
		"name":        zone.Name,
		"id":          strconv.FormatUint(zone.Id, 10),
		"dnsName":     zone.DnsName,
		"description": zone.Description,
		"nameServers": zone.NameServers,
		"visibility":  zone.Visibility,
		"labels":      zone.Labels,
		// "forwardingConfig":        zone.ForwardingConfig,
		// "reverseLookupConfig":     zone.ReverseLookupConfig,
	}
	if zone.DnsName != "" && zone.Visibility == "public" {
		properties["publicDomain"] = zone.DnsName
	}
	return properties
}

type GCPNetworkingFanOut struct {
	*base.GcpBaseLink
}

// creates a link to fan out to all networking resources list links in a project
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
		chain.NewChain(NewGcpGlobalAddressListLink()),
		chain.NewChain(NewGcpRegionalAddressListLink()),
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
