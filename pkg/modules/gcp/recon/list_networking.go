package recon

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"sync"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/utils"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/option"
)

func init() {
	plugin.Register(&GCPListNetworkingModule{})
}

// GCPListNetworkingModule lists all networking resources in a GCP project
type GCPListNetworkingModule struct{}

func (m *GCPListNetworkingModule) ID() string {
	return "networking-list"
}

func (m *GCPListNetworkingModule) Name() string {
	return "GCP List Networking"
}

func (m *GCPListNetworkingModule) Description() string {
	return "List all networking resources in a GCP project."
}

func (m *GCPListNetworkingModule) Platform() plugin.Platform {
	return plugin.PlatformGCP
}

func (m *GCPListNetworkingModule) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *GCPListNetworkingModule) OpsecLevel() string {
	return "moderate"
}

func (m *GCPListNetworkingModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *GCPListNetworkingModule) References() []string {
	return []string{}
}

func (m *GCPListNetworkingModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "project",
			Description: "GCP project ID (e.g., my-project-123456)",
			Type:        "string",
			Required:    true,
		},
		{
			Name:        "creds-file",
			Description: "Path to GCP service account credentials JSON file",
			Type:        "string",
		},
	}
}

func (m *GCPListNetworkingModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Get project parameter
	projectID, ok := cfg.Args["project"].(string)
	if !ok || projectID == "" {
		return nil, fmt.Errorf("project parameter is required")
	}

	// Setup credentials
	var clientOpts []option.ClientOption
	if credsFile, ok := cfg.Args["creds-file"].(string); ok && credsFile != "" {
		creds, err := google.CredentialsFromJSON(cfg.Context, []byte(credsFile))
		if err != nil {
			return nil, fmt.Errorf("failed to load credentials: %w", err)
		}
		clientOpts = append(clientOpts, option.WithCredentials(creds))
	} else {
		creds, err := google.FindDefaultCredentials(cfg.Context)
		if err != nil {
			return nil, fmt.Errorf("failed to find default credentials: %w", err)
		}
		clientOpts = append(clientOpts, option.WithCredentials(creds))
	}

	results := []plugin.Result{}

	// Get project info first
	resourceManagerService, err := cloudresourcemanager.NewService(cfg.Context, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource manager service: %w", err)
	}

	project, err := resourceManagerService.Projects.Get(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get project %s: %w", projectID, err)
	}

	projectResource := &output.CloudResource{
		Platform:     "gcp",
		ResourceType: "cloudresourcemanager.googleapis.com/Project",
		ResourceID:   fmt.Sprintf("projects/%s", project.ProjectId),
		AccountRef:   fmt.Sprintf("%s/%s", project.Parent.Type, project.Parent.Id),
		DisplayName:  project.Name,
		Properties: map[string]any{
			"projectNumber":  strconv.FormatInt(project.ProjectNumber, 10),
			"lifecycleState": project.LifecycleState,
			"parentType":     project.Parent.Type,
			"parentId":       project.Parent.Id,
			"labels":         project.Labels,
		},
	}

	// Initialize compute service
	computeService, err := compute.NewService(cfg.Context, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute service: %w", err)
	}

	// Initialize DNS service
	dnsService, err := dns.NewService(cfg.Context, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create dns service: %w", err)
	}

	// Collect all networking resources in parallel
	var wg sync.WaitGroup
	var mu sync.Mutex
	var collectionErr error

	// Global forwarding rules
	wg.Add(1)
	go func() {
		defer wg.Done()
		resources, err := m.listGlobalForwardingRules(cfg.Context, computeService, projectID)
		if err != nil {
			mu.Lock()
			collectionErr = fmt.Errorf("failed to list global forwarding rules: %w", err)
			mu.Unlock()
			return
		}
		mu.Lock()
		results = append(results, resources...)
		mu.Unlock()
	}()

	// Regional forwarding rules
	wg.Add(1)
	go func() {
		defer wg.Done()
		resources, err := m.listRegionalForwardingRules(cfg.Context, computeService, projectID)
		if err != nil {
			mu.Lock()
			collectionErr = fmt.Errorf("failed to list regional forwarding rules: %w", err)
			mu.Unlock()
			return
		}
		mu.Lock()
		results = append(results, resources...)
		mu.Unlock()
	}()

	// Global addresses
	wg.Add(1)
	go func() {
		defer wg.Done()
		resources, err := m.listGlobalAddresses(cfg.Context, computeService, projectID)
		if err != nil {
			mu.Lock()
			collectionErr = fmt.Errorf("failed to list global addresses: %w", err)
			mu.Unlock()
			return
		}
		mu.Lock()
		results = append(results, resources...)
		mu.Unlock()
	}()

	// Regional addresses
	wg.Add(1)
	go func() {
		defer wg.Done()
		resources, err := m.listRegionalAddresses(cfg.Context, computeService, projectID)
		if err != nil {
			mu.Lock()
			collectionErr = fmt.Errorf("failed to list regional addresses: %w", err)
			mu.Unlock()
			return
		}
		mu.Lock()
		results = append(results, resources...)
		mu.Unlock()
	}()

	// DNS managed zones
	wg.Add(1)
	go func() {
		defer wg.Done()
		resources, err := m.listDnsManagedZones(cfg.Context, dnsService, projectID)
		if err != nil {
			mu.Lock()
			collectionErr = fmt.Errorf("failed to list DNS managed zones: %w", err)
			mu.Unlock()
			return
		}
		mu.Lock()
		results = append(results, resources...)
		mu.Unlock()
	}()

	wg.Wait()

	if collectionErr != nil {
		return nil, collectionErr
	}

	// Add project resource to metadata
	for i := range results {
		if results[i].Metadata == nil {
			results[i].Metadata = make(map[string]any)
		}
		results[i].Metadata["project"] = projectResource
	}

	return results, nil
}

func (m *GCPListNetworkingModule) listGlobalForwardingRules(ctx context.Context, computeService *compute.Service, projectID string) ([]plugin.Result, error) {
	results := []plugin.Result{}
	globalListReq := computeService.GlobalForwardingRules.List(projectID)
	err := globalListReq.Pages(ctx, func(page *compute.ForwardingRuleList) error {
		for _, rule := range page.Items {
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
			results = append(results, plugin.Result{
				Data: &output.CloudResource{
					Platform:     "gcp",
					ResourceType: "compute.googleapis.com/GlobalForwardingRule",
					ResourceID:   fmt.Sprintf("projects/%s/global/forwardingRules/%s", projectID, rule.Name),
					AccountRef:   projectID,
					DisplayName:  rule.Name,
					Properties:   properties,
				},
			})
		}
		return nil
	})
	if err != nil {
		return nil, utils.HandleGcpError(err, "failed to list global forwarding rules")
	}
	return results, nil
}

func (m *GCPListNetworkingModule) listRegionalForwardingRules(ctx context.Context, computeService *compute.Service, projectID string) ([]plugin.Result, error) {
	results := []plugin.Result{}
	regionsListCall := computeService.Regions.List(projectID)
	regionsResp, err := regionsListCall.Do()
	if err != nil {
		return nil, utils.HandleGcpError(err, "failed to list regions in project")
	}

	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, region := range regionsResp.Items {
		wg.Add(1)
		sem <- struct{}{}
		go func(regionName string) {
			defer wg.Done()
			defer func() { <-sem }()
			regionalListReq := computeService.ForwardingRules.List(projectID, regionName)
			err := regionalListReq.Pages(ctx, func(page *compute.ForwardingRuleList) error {
				for _, rule := range page.Items {
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
					mu.Lock()
					results = append(results, plugin.Result{
						Data: &output.CloudResource{
							Platform:     "gcp",
							ResourceType: "compute.googleapis.com/ForwardingRule",
							ResourceID:   fmt.Sprintf("projects/%s/regions/%s/forwardingRules/%s", projectID, regionName, rule.Name),
							AccountRef:   projectID,
							Region:       regionName,
							DisplayName:  rule.Name,
							Properties:   properties,
						},
					})
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

func (m *GCPListNetworkingModule) listGlobalAddresses(ctx context.Context, computeService *compute.Service, projectID string) ([]plugin.Result, error) {
	results := []plugin.Result{}
	globalListReq := computeService.GlobalAddresses.List(projectID)
	err := globalListReq.Pages(ctx, func(page *compute.AddressList) error {
		for _, address := range page.Items {
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
			results = append(results, plugin.Result{
				Data: &output.CloudResource{
					Platform:     "gcp",
					ResourceType: "compute.googleapis.com/GlobalAddress",
					ResourceID:   fmt.Sprintf("projects/%s/global/addresses/%s", projectID, address.Name),
					AccountRef:   projectID,
					DisplayName:  address.Name,
					Properties:   properties,
				},
			})
		}
		return nil
	})
	if err != nil {
		return nil, utils.HandleGcpError(err, "failed to list global addresses")
	}
	return results, nil
}

func (m *GCPListNetworkingModule) listRegionalAddresses(ctx context.Context, computeService *compute.Service, projectID string) ([]plugin.Result, error) {
	results := []plugin.Result{}
	regionsListCall := computeService.Regions.List(projectID)
	regionsResp, err := regionsListCall.Do()
	if err != nil {
		return nil, utils.HandleGcpError(err, "failed to list regions in project")
	}

	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, region := range regionsResp.Items {
		wg.Add(1)
		sem <- struct{}{}
		go func(regionName string) {
			defer wg.Done()
			defer func() { <-sem }()
			regionalListReq := computeService.Addresses.List(projectID, regionName)
			err := regionalListReq.Pages(ctx, func(page *compute.AddressList) error {
				for _, address := range page.Items {
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
					mu.Lock()
					results = append(results, plugin.Result{
						Data: &output.CloudResource{
							Platform:     "gcp",
							ResourceType: "compute.googleapis.com/Address",
							ResourceID:   fmt.Sprintf("projects/%s/regions/%s/addresses/%s", projectID, regionName, address.Name),
							AccountRef:   projectID,
							Region:       regionName,
							DisplayName:  address.Name,
							Properties:   properties,
						},
					})
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

func (m *GCPListNetworkingModule) listDnsManagedZones(ctx context.Context, dnsService *dns.Service, projectID string) ([]plugin.Result, error) {
	results := []plugin.Result{}
	listReq := dnsService.ManagedZones.List(projectID)
	err := listReq.Pages(ctx, func(page *dns.ManagedZonesListResponse) error {
		for _, zone := range page.ManagedZones {
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
			results = append(results, plugin.Result{
				Data: &output.CloudResource{
					Platform:     "gcp",
					ResourceType: "dns.googleapis.com/ManagedZone",
					ResourceID:   fmt.Sprintf("projects/%s/managedZones/%s", projectID, zone.Name),
					AccountRef:   projectID,
					DisplayName:  zone.DnsName,
					Properties:   properties,
				},
			})
		}
		return nil
	})
	if err != nil {
		return nil, utils.HandleGcpError(err, "failed to list DNS managed zones")
	}
	return results, nil
}
