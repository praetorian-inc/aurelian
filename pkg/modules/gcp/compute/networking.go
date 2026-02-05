package compute

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"sync"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/option"
)

// GlobalForwardingRuleList lists all global forwarding rules in a project
type GlobalForwardingRuleList struct{}

func init() {
	plugin.Register(&GlobalForwardingRuleList{})
}

func (m *GlobalForwardingRuleList) ID() string {
	return "gcp-global-forwarding-rule-list"
}

func (m *GlobalForwardingRuleList) Name() string {
	return "GCP Global Forwarding Rule List"
}

func (m *GlobalForwardingRuleList) Description() string {
	return "Lists all global forwarding rules in a GCP project"
}

func (m *GlobalForwardingRuleList) Platform() plugin.Platform {
	return plugin.PlatformGCP
}

func (m *GlobalForwardingRuleList) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *GlobalForwardingRuleList) OpsecLevel() string {
	return "low"
}

func (m *GlobalForwardingRuleList) Authors() []string {
	return []string{"Praetorian"}
}

func (m *GlobalForwardingRuleList) References() []string {
	return []string{
		"https://cloud.google.com/compute/docs/reference/rest/v1/globalForwardingRules",
	}
}

func (m *GlobalForwardingRuleList) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("project", "GCP project ID", plugin.WithRequired()),
		plugin.NewParam[string]("credentials", "Path to credentials JSON file"),
	}
}

func (m *GlobalForwardingRuleList) Run(cfg plugin.Config) ([]plugin.Result, error) {
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	projectID, _ := cfg.Args["project"].(string)
	if projectID == "" {
		return nil, fmt.Errorf("project is required")
	}

	var opts []option.ClientOption
	if creds, ok := cfg.Args["credentials"].(string); ok && creds != "" {
		opts = append(opts, option.WithCredentialsFile(creds))
	}

	computeService, err := compute.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute service: %w", err)
	}

	var results []plugin.Result
	globalListReq := computeService.GlobalForwardingRules.List(projectID)
	err = globalListReq.Pages(ctx, func(page *compute.ForwardingRuleList) error {
		for _, rule := range page.Items {
			properties := postProcessForwardingRule(rule)
			result := plugin.Result{
				Data: map[string]any{
					"platform":      "gcp",
					"resource_type": "compute.googleapis.com/GlobalForwardingRule",
					"resource_id":   fmt.Sprintf("projects/%s/global/forwardingRules/%s", projectID, rule.Name),
					"account_ref":   projectID,
					"display_name":  rule.Name,
					"properties":    properties,
				},
				Metadata: map[string]any{
					"module_id": m.ID(),
					"platform":  "gcp",
				},
			}
			results = append(results, result)
		}
		return nil
	})
	return results, err
}

// RegionalForwardingRuleList lists all regional forwarding rules in a project
type RegionalForwardingRuleList struct{}

func init() {
	plugin.Register(&RegionalForwardingRuleList{})
}

func (m *RegionalForwardingRuleList) ID() string {
	return "gcp-regional-forwarding-rule-list"
}

func (m *RegionalForwardingRuleList) Name() string {
	return "GCP Regional Forwarding Rule List"
}

func (m *RegionalForwardingRuleList) Description() string {
	return "Lists all regional forwarding rules across all regions in a GCP project"
}

func (m *RegionalForwardingRuleList) Platform() plugin.Platform {
	return plugin.PlatformGCP
}

func (m *RegionalForwardingRuleList) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *RegionalForwardingRuleList) OpsecLevel() string {
	return "low"
}

func (m *RegionalForwardingRuleList) Authors() []string {
	return []string{"Praetorian"}
}

func (m *RegionalForwardingRuleList) References() []string {
	return []string{
		"https://cloud.google.com/compute/docs/reference/rest/v1/forwardingRules",
	}
}

func (m *RegionalForwardingRuleList) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("project", "GCP project ID", plugin.WithRequired()),
		plugin.NewParam[string]("credentials", "Path to credentials JSON file"),
	}
}

func (m *RegionalForwardingRuleList) Run(cfg plugin.Config) ([]plugin.Result, error) {
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	projectID, _ := cfg.Args["project"].(string)
	if projectID == "" {
		return nil, fmt.Errorf("project is required")
	}

	var opts []option.ClientOption
	if creds, ok := cfg.Args["credentials"].(string); ok && creds != "" {
		opts = append(opts, option.WithCredentialsFile(creds))
	}

	computeService, err := compute.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute service: %w", err)
	}

	regionsListCall := computeService.Regions.List(projectID)
	regionsResp, err := regionsListCall.Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list regions in project: %w", err)
	}

	var results []plugin.Result
	var mu sync.Mutex
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for _, region := range regionsResp.Items {
		wg.Add(1)
		sem <- struct{}{}

		go func(regionName string) {
			defer wg.Done()
			defer func() { <-sem }()

			regionalListReq := computeService.ForwardingRules.List(projectID, regionName)
			err := regionalListReq.Pages(ctx, func(page *compute.ForwardingRuleList) error {
				for _, rule := range page.Items {
					result := plugin.Result{
						Data: map[string]any{
							"platform":      "gcp",
							"resource_type": "compute.googleapis.com/ForwardingRule",
							"resource_id":   fmt.Sprintf("projects/%s/regions/%s/forwardingRules/%s", projectID, regionName, rule.Name),
							"account_ref":   projectID,
							"region":        regionName,
							"display_name":  rule.Name,
							"properties":    postProcessForwardingRule(rule),
						},
						Metadata: map[string]any{
							"module_id": m.ID(),
							"platform":  "gcp",
							"region":    regionName,
						},
					}

					mu.Lock()
					results = append(results, result)
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
	return results, nil
}

// GlobalAddressList lists all global addresses in a project
type GlobalAddressList struct{}

func init() {
	plugin.Register(&GlobalAddressList{})
}

func (m *GlobalAddressList) ID() string {
	return "gcp-global-address-list"
}

func (m *GlobalAddressList) Name() string {
	return "GCP Global Address List"
}

func (m *GlobalAddressList) Description() string {
	return "Lists all global addresses in a GCP project"
}

func (m *GlobalAddressList) Platform() plugin.Platform {
	return plugin.PlatformGCP
}

func (m *GlobalAddressList) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *GlobalAddressList) OpsecLevel() string {
	return "low"
}

func (m *GlobalAddressList) Authors() []string {
	return []string{"Praetorian"}
}

func (m *GlobalAddressList) References() []string {
	return []string{
		"https://cloud.google.com/compute/docs/reference/rest/v1/globalAddresses",
	}
}

func (m *GlobalAddressList) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("project", "GCP project ID", plugin.WithRequired()),
		plugin.NewParam[string]("credentials", "Path to credentials JSON file"),
	}
}

func (m *GlobalAddressList) Run(cfg plugin.Config) ([]plugin.Result, error) {
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	projectID, _ := cfg.Args["project"].(string)
	if projectID == "" {
		return nil, fmt.Errorf("project is required")
	}

	var opts []option.ClientOption
	if creds, ok := cfg.Args["credentials"].(string); ok && creds != "" {
		opts = append(opts, option.WithCredentialsFile(creds))
	}

	computeService, err := compute.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute service: %w", err)
	}

	var results []plugin.Result
	globalListReq := computeService.GlobalAddresses.List(projectID)
	err = globalListReq.Pages(ctx, func(page *compute.AddressList) error {
		for _, address := range page.Items {
			result := plugin.Result{
				Data: map[string]any{
					"platform":      "gcp",
					"resource_type": "compute.googleapis.com/GlobalAddress",
					"resource_id":   fmt.Sprintf("projects/%s/global/addresses/%s", projectID, address.Name),
					"account_ref":   projectID,
					"display_name":  address.Name,
					"properties":    postProcessAddress(address),
				},
				Metadata: map[string]any{
					"module_id": m.ID(),
					"platform":  "gcp",
				},
			}
			results = append(results, result)
		}
		return nil
	})
	return results, err
}

// RegionalAddressList lists all regional addresses in a project
type RegionalAddressList struct{}

func init() {
	plugin.Register(&RegionalAddressList{})
}

func (m *RegionalAddressList) ID() string {
	return "gcp-regional-address-list"
}

func (m *RegionalAddressList) Name() string {
	return "GCP Regional Address List"
}

func (m *RegionalAddressList) Description() string {
	return "Lists all regional addresses across all regions in a GCP project"
}

func (m *RegionalAddressList) Platform() plugin.Platform {
	return plugin.PlatformGCP
}

func (m *RegionalAddressList) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *RegionalAddressList) OpsecLevel() string {
	return "low"
}

func (m *RegionalAddressList) Authors() []string {
	return []string{"Praetorian"}
}

func (m *RegionalAddressList) References() []string {
	return []string{
		"https://cloud.google.com/compute/docs/reference/rest/v1/addresses",
	}
}

func (m *RegionalAddressList) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("project", "GCP project ID", plugin.WithRequired()),
		plugin.NewParam[string]("credentials", "Path to credentials JSON file"),
	}
}

func (m *RegionalAddressList) Run(cfg plugin.Config) ([]plugin.Result, error) {
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	projectID, _ := cfg.Args["project"].(string)
	if projectID == "" {
		return nil, fmt.Errorf("project is required")
	}

	var opts []option.ClientOption
	if creds, ok := cfg.Args["credentials"].(string); ok && creds != "" {
		opts = append(opts, option.WithCredentialsFile(creds))
	}

	computeService, err := compute.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute service: %w", err)
	}

	regionsListCall := computeService.Regions.List(projectID)
	regionsResp, err := regionsListCall.Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list regions in project: %w", err)
	}

	var results []plugin.Result
	var mu sync.Mutex
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for _, region := range regionsResp.Items {
		wg.Add(1)
		sem <- struct{}{}

		go func(regionName string) {
			defer wg.Done()
			defer func() { <-sem }()

			regionalListReq := computeService.Addresses.List(projectID, regionName)
			err := regionalListReq.Pages(ctx, func(page *compute.AddressList) error {
				for _, address := range page.Items {
					result := plugin.Result{
						Data: map[string]any{
							"platform":      "gcp",
							"resource_type": "compute.googleapis.com/Address",
							"resource_id":   fmt.Sprintf("projects/%s/regions/%s/addresses/%s", projectID, regionName, address.Name),
							"account_ref":   projectID,
							"region":        regionName,
							"display_name":  address.Name,
							"properties":    postProcessAddress(address),
						},
						Metadata: map[string]any{
							"module_id": m.ID(),
							"platform":  "gcp",
							"region":    regionName,
						},
					}

					mu.Lock()
					results = append(results, result)
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
	return results, nil
}

// DnsManagedZoneList lists all DNS managed zones in a project
type DnsManagedZoneList struct{}

func init() {
	plugin.Register(&DnsManagedZoneList{})
}

func (m *DnsManagedZoneList) ID() string {
	return "gcp-dns-managed-zone-list"
}

func (m *DnsManagedZoneList) Name() string {
	return "GCP DNS Managed Zone List"
}

func (m *DnsManagedZoneList) Description() string {
	return "Lists all DNS managed zones in a GCP project"
}

func (m *DnsManagedZoneList) Platform() plugin.Platform {
	return plugin.PlatformGCP
}

func (m *DnsManagedZoneList) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *DnsManagedZoneList) OpsecLevel() string {
	return "low"
}

func (m *DnsManagedZoneList) Authors() []string {
	return []string{"Praetorian"}
}

func (m *DnsManagedZoneList) References() []string {
	return []string{
		"https://cloud.google.com/dns/docs/reference/v1/managedZones",
	}
}

func (m *DnsManagedZoneList) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("project", "GCP project ID", plugin.WithRequired()),
		plugin.NewParam[string]("credentials", "Path to credentials JSON file"),
	}
}

func (m *DnsManagedZoneList) Run(cfg plugin.Config) ([]plugin.Result, error) {
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	projectID, _ := cfg.Args["project"].(string)
	if projectID == "" {
		return nil, fmt.Errorf("project is required")
	}

	var opts []option.ClientOption
	if creds, ok := cfg.Args["credentials"].(string); ok && creds != "" {
		opts = append(opts, option.WithCredentialsFile(creds))
	}

	dnsService, err := dns.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create dns service: %w", err)
	}

	var results []plugin.Result
	listReq := dnsService.ManagedZones.List(projectID)
	err = listReq.Pages(ctx, func(page *dns.ManagedZonesListResponse) error {
		for _, zone := range page.ManagedZones {
			result := plugin.Result{
				Data: map[string]any{
					"platform":      "gcp",
					"resource_type": "dns.googleapis.com/ManagedZone",
					"resource_id":   fmt.Sprintf("projects/%s/managedZones/%s", projectID, zone.Name),
					"account_ref":   projectID,
					"display_name":  zone.DnsName,
					"properties":    postProcessDnsZone(zone),
				},
				Metadata: map[string]any{
					"module_id": m.ID(),
					"platform":  "gcp",
				},
			}
			results = append(results, result)
		}
		return nil
	})
	return results, err
}

// ------------------------------------------------------------------------------------------------
// Helper functions

func postProcessForwardingRule(rule *compute.ForwardingRule) map[string]any {
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
		// Simple check: if contains ":" it's IPv6, otherwise IPv4
		if containsColon(rule.IPAddress) {
			properties["publicIPv6"] = rule.IPAddress
		} else {
			properties["publicIP"] = rule.IPAddress
		}
	}
	return properties
}

func postProcessAddress(address *compute.Address) map[string]any {
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
		if containsColon(address.Address) {
			properties["publicIPv6"] = address.Address
		} else {
			properties["publicIP"] = address.Address
		}
	}
	return properties
}

func postProcessDnsZone(zone *dns.ManagedZone) map[string]any {
	properties := map[string]any{
		"name":        zone.Name,
		"id":          strconv.FormatUint(zone.Id, 10),
		"dnsName":     zone.DnsName,
		"description": zone.Description,
		"nameServers": zone.NameServers,
		"visibility":  zone.Visibility,
		"labels":      zone.Labels,
	}

	if zone.DnsName != "" && zone.Visibility == "public" {
		properties["publicDomain"] = zone.DnsName
	}
	return properties
}

func containsColon(s string) bool {
	for _, c := range s {
		if c == ':' {
			return true
		}
	}
	return false
}
