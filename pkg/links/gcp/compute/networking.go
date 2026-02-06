package compute

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"sync"

	"github.com/praetorian-inc/aurelian/pkg/links/gcp/common"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/utils"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/option"
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
	*plugin.BaseLink
	computeService *compute.Service
	ClientOptions  []option.ClientOption
}

// creates a link to list all global forwarding rules in a project
func NewGcpGlobalForwardingRuleListLink(args map[string]any) *GcpGlobalForwardingRuleListLink {
	return &GcpGlobalForwardingRuleListLink{
		BaseLink: plugin.NewBaseLink("gcp-global-forwarding-rule-list", args),
	}
}

func (g *GcpGlobalForwardingRuleListLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("credentials", "Path to GCP credentials file"),
	}
}

func (g *GcpGlobalForwardingRuleListLink) Process(ctx context.Context, input any) ([]any, error) {
	// Initialize service on first call
	if g.computeService == nil {
		if creds, ok := g.Arg("credentials").(string); ok && creds != "" {
			g.ClientOptions = []option.ClientOption{option.WithCredentialsFile(creds)}
		}
		var err error
		g.computeService, err = compute.NewService(ctx, g.ClientOptions...)
		if err != nil {
			return nil, fmt.Errorf("failed to create compute service: %w", err)
		}
	}

	resource, ok := input.(tab.GCPResource)
	if !ok {
		return nil, fmt.Errorf("expected tab.GCPResource input, got %T", input)
	}

	if resource.ResourceType != tab.GCPResourceProject {
		return nil, nil
	}

	projectId := resource.Name
	globalListReq := g.computeService.GlobalForwardingRules.List(projectId)

	var outputs []any
	err := globalListReq.Pages(ctx, func(page *compute.ForwardingRuleList) error {
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
			outputs = append(outputs, gcpForwardingRule)
		}
		return nil
	})

	if err != nil {
		return nil, common.HandleGcpError(err, "failed to list global forwarding rules")
	}

	return outputs, nil
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
	*plugin.BaseLink
	computeService *compute.Service
	ClientOptions  []option.ClientOption
}

// creates a link to list all regional forwarding rules in a project
func NewGcpRegionalForwardingRuleListLink(args map[string]any) *GcpRegionalForwardingRuleListLink {
	return &GcpRegionalForwardingRuleListLink{
		BaseLink: plugin.NewBaseLink("gcp-regional-forwarding-rule-list", args),
	}
}

func (g *GcpRegionalForwardingRuleListLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("credentials", "Path to GCP credentials file"),
	}
}

func (g *GcpRegionalForwardingRuleListLink) Process(ctx context.Context, input any) ([]any, error) {
	// Initialize service on first call
	if g.computeService == nil {
		if creds, ok := g.Arg("credentials").(string); ok && creds != "" {
			g.ClientOptions = []option.ClientOption{option.WithCredentialsFile(creds)}
		}
		var err error
		g.computeService, err = compute.NewService(ctx, g.ClientOptions...)
		if err != nil {
			return nil, fmt.Errorf("failed to create compute service: %w", err)
		}
	}

	resource, ok := input.(tab.GCPResource)
	if !ok {
		return nil, fmt.Errorf("expected tab.GCPResource input, got %T", input)
	}

	if resource.ResourceType != tab.GCPResourceProject {
		return nil, nil
	}

	projectId := resource.Name
	regionsListCall := g.computeService.Regions.List(projectId)
	regionsResp, err := regionsListCall.Do()
	if err != nil {
		return nil, common.HandleGcpError(err, "failed to list regions in project")
	}

	var outputs []any
	var mu sync.Mutex
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for _, region := range regionsResp.Items {
		wg.Add(1)
		sem <- struct{}{}
		go func(regionName string) {
			defer wg.Done()
			defer func() { <-sem }()

			regionalListReq := g.computeService.ForwardingRules.List(projectId, regionName)
			err := regionalListReq.Pages(ctx, func(page *compute.ForwardingRuleList) error {
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

					mu.Lock()
					outputs = append(outputs, gcpForwardingRule)
					mu.Unlock()
				}
				return nil
			})
			if err != nil {
				slog.Error("Failed to list forwarding rules in region", "error", err, "region", regionName)
			}
		}(region.Name)
	}
	wg.Wait()

	return outputs, nil
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
	*plugin.BaseLink
	computeService *compute.Service
	ClientOptions  []option.ClientOption
}

// creates a link to list all global addresses in a project
func NewGcpGlobalAddressListLink(args map[string]any) *GcpGlobalAddressListLink {
	return &GcpGlobalAddressListLink{
		BaseLink: plugin.NewBaseLink("gcp-global-address-list", args),
	}
}

func (g *GcpGlobalAddressListLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("credentials", "Path to GCP credentials file"),
	}
}

func (g *GcpGlobalAddressListLink) Process(ctx context.Context, input any) ([]any, error) {
	// Initialize service on first call
	if g.computeService == nil {
		if creds, ok := g.Arg("credentials").(string); ok && creds != "" {
			g.ClientOptions = []option.ClientOption{option.WithCredentialsFile(creds)}
		}
		var err error
		g.computeService, err = compute.NewService(ctx, g.ClientOptions...)
		if err != nil {
			return nil, fmt.Errorf("failed to create compute service: %w", err)
		}
	}

	resource, ok := input.(tab.GCPResource)
	if !ok {
		return nil, fmt.Errorf("expected tab.GCPResource input, got %T", input)
	}

	if resource.ResourceType != tab.GCPResourceProject {
		return nil, nil
	}

	projectId := resource.Name
	globalListReq := g.computeService.GlobalAddresses.List(projectId)

	var outputs []any
	err := globalListReq.Pages(ctx, func(page *compute.AddressList) error {
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
			outputs = append(outputs, gcpGlobalAddress)
		}
		return nil
	})

	if err != nil {
		return nil, common.HandleGcpError(err, "failed to list global addresses")
	}

	return outputs, nil
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
	*plugin.BaseLink
	computeService *compute.Service
	ClientOptions  []option.ClientOption
}

// creates a link to list all regional addresses in a project
func NewGcpRegionalAddressListLink(args map[string]any) *GcpRegionalAddressListLink {
	return &GcpRegionalAddressListLink{
		BaseLink: plugin.NewBaseLink("gcp-regional-address-list", args),
	}
}

func (g *GcpRegionalAddressListLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("credentials", "Path to GCP credentials file"),
	}
}

func (g *GcpRegionalAddressListLink) Process(ctx context.Context, input any) ([]any, error) {
	// Initialize service on first call
	if g.computeService == nil {
		if creds, ok := g.Arg("credentials").(string); ok && creds != "" {
			g.ClientOptions = []option.ClientOption{option.WithCredentialsFile(creds)}
		}
		var err error
		g.computeService, err = compute.NewService(ctx, g.ClientOptions...)
		if err != nil {
			return nil, fmt.Errorf("failed to create compute service: %w", err)
		}
	}

	resource, ok := input.(tab.GCPResource)
	if !ok {
		return nil, fmt.Errorf("expected tab.GCPResource input, got %T", input)
	}

	if resource.ResourceType != tab.GCPResourceProject {
		return nil, nil
	}

	projectId := resource.Name
	regionsListCall := g.computeService.Regions.List(projectId)
	regionsResp, err := regionsListCall.Do()
	if err != nil {
		return nil, common.HandleGcpError(err, "failed to list regions in project")
	}

	var outputs []any
	var mu sync.Mutex
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for _, region := range regionsResp.Items {
		wg.Add(1)
		sem <- struct{}{}
		go func(regionName string) {
			defer wg.Done()
			defer func() { <-sem }()

			regionalListReq := g.computeService.Addresses.List(projectId, regionName)
			err := regionalListReq.Pages(ctx, func(page *compute.AddressList) error {
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

					mu.Lock()
					outputs = append(outputs, gcpRegionalAddress)
					mu.Unlock()
				}
				return nil
			})
			if err != nil {
				slog.Error("Failed to list addresses in region", "error", err, "region", regionName)
			}
		}(region.Name)
	}
	wg.Wait()

	return outputs, nil
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
	*plugin.BaseLink
	dnsService    *dns.Service
	ClientOptions []option.ClientOption
}

// creates a link to list all DNS managed zones in a project
func NewGcpDnsManagedZoneListLink(args map[string]any) *GcpDnsManagedZoneListLink {
	return &GcpDnsManagedZoneListLink{
		BaseLink: plugin.NewBaseLink("gcp-dns-managed-zone-list", args),
	}
}

func (g *GcpDnsManagedZoneListLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("credentials", "Path to GCP credentials file"),
	}
}

func (g *GcpDnsManagedZoneListLink) Process(ctx context.Context, input any) ([]any, error) {
	// Initialize service on first call
	if g.dnsService == nil {
		if creds, ok := g.Arg("credentials").(string); ok && creds != "" {
			g.ClientOptions = []option.ClientOption{option.WithCredentialsFile(creds)}
		}
		var err error
		g.dnsService, err = dns.NewService(ctx, g.ClientOptions...)
		if err != nil {
			return nil, fmt.Errorf("failed to create dns service: %w", err)
		}
	}

	resource, ok := input.(tab.GCPResource)
	if !ok {
		return nil, fmt.Errorf("expected tab.GCPResource input, got %T", input)
	}

	if resource.ResourceType != tab.GCPResourceProject {
		return nil, nil
	}

	projectId := resource.Name
	listReq := g.dnsService.ManagedZones.List(projectId)

	var outputs []any
	err := listReq.Pages(ctx, func(page *dns.ManagedZonesListResponse) error {
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
			outputs = append(outputs, gcpDnsZone)
		}
		return nil
	})

	if err != nil {
		return nil, common.HandleGcpError(err, "failed to list DNS managed zones")
	}

	return outputs, nil
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
	*plugin.BaseLink
}

// creates a link to fan out to all networking resources list links in a project
func NewGCPNetworkingFanOut(args map[string]any) *GCPNetworkingFanOut {
	return &GCPNetworkingFanOut{
		BaseLink: plugin.NewBaseLink("gcp-networking-fanout", args),
	}
}

func (g *GCPNetworkingFanOut) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("credentials", "Path to GCP credentials file"),
	}
}

func (g *GCPNetworkingFanOut) Process(ctx context.Context, input any) ([]any, error) {
	project, ok := input.(tab.GCPResource)
	if !ok {
		return nil, fmt.Errorf("expected tab.GCPResource input, got %T", input)
	}

	if project.ResourceType != tab.GCPResourceProject {
		return nil, nil
	}

	// Create child links with same args
	links := []plugin.Link{
		NewGcpGlobalForwardingRuleListLink(g.BaseLink.Args()),
		NewGcpRegionalForwardingRuleListLink(g.BaseLink.Args()),
		NewGcpGlobalAddressListLink(g.BaseLink.Args()),
		NewGcpRegionalAddressListLink(g.BaseLink.Args()),
		NewGcpDnsManagedZoneListLink(g.BaseLink.Args()),
	}

	var allOutputs []any
	for _, link := range links {
		outputs, err := link.Process(ctx, project)
		if err != nil {
			slog.Error("Error in GCP networking fan out", "error", err, "link", link)
			// Continue processing other links even if one fails (lax strictness)
			continue
		}
		allOutputs = append(allOutputs, outputs...)
	}

	return allOutputs, nil
}
