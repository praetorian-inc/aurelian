package compute

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"sync"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
)

// InstanceInfo retrieves information about a single GCP compute instance
type InstanceInfo struct{}

func init() {
	plugin.Register(&InstanceInfo{})
}

func (m *InstanceInfo) ID() string {
	return "gcp-instance-info"
}

func (m *InstanceInfo) Name() string {
	return "GCP Instance Info"
}

func (m *InstanceInfo) Description() string {
	return "Retrieves detailed information about a specific GCP compute instance"
}

func (m *InstanceInfo) Platform() plugin.Platform {
	return plugin.PlatformGCP
}

func (m *InstanceInfo) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *InstanceInfo) OpsecLevel() string {
	return "low"
}

func (m *InstanceInfo) Authors() []string {
	return []string{"Praetorian"}
}

func (m *InstanceInfo) References() []string {
	return []string{
		"https://cloud.google.com/compute/docs/reference/rest/v1/instances",
	}
}

func (m *InstanceInfo) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("project", "GCP project ID", plugin.WithRequired()),
		plugin.NewParam[string]("zone", "GCP zone", plugin.WithRequired()),
		plugin.NewParam[string]("instance", "Instance name", plugin.WithRequired()),
		plugin.NewParam[string]("credentials", "Path to credentials JSON file"),
	}
}

func (m *InstanceInfo) Run(cfg plugin.Config) ([]plugin.Result, error) {
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	// Get required parameters
	projectID, _ := cfg.Args["project"].(string)
	zone, _ := cfg.Args["zone"].(string)
	instanceName, _ := cfg.Args["instance"].(string)

	if projectID == "" || zone == "" || instanceName == "" {
		return nil, fmt.Errorf("project, zone, and instance are required")
	}

	// Setup credentials
	var opts []option.ClientOption
	if creds, ok := cfg.Args["credentials"].(string); ok && creds != "" {
		opts = append(opts, option.WithCredentialsFile(creds))
	}

	// Create compute service
	computeService, err := compute.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute service: %w", err)
	}

	// Get instance
	instance, err := computeService.Instances.Get(projectID, zone, instanceName).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get instance %s: %w", instanceName, err)
	}

	// Create result
	result := plugin.Result{
		Data: map[string]any{
			"platform":      "gcp",
			"resource_type": "compute.googleapis.com/Instance",
			"resource_id":   fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zone, strconv.FormatUint(instance.Id, 10)),
			"account_ref":   projectID,
			"region":        zone,
			"display_name":  instance.Name,
			"properties":    postProcessComputeInstance(instance),
		},
		Metadata: map[string]any{
			"module_id": m.ID(),
			"platform":  "gcp",
		},
	}

	return []plugin.Result{result}, nil
}

// InstanceList lists all compute instances in a GCP project
type InstanceList struct{}

func init() {
	plugin.Register(&InstanceList{})
}

func (m *InstanceList) ID() string {
	return "gcp-instance-list"
}

func (m *InstanceList) Name() string {
	return "GCP Instance List"
}

func (m *InstanceList) Description() string {
	return "Lists all compute instances across all zones in a GCP project"
}

func (m *InstanceList) Platform() plugin.Platform {
	return plugin.PlatformGCP
}

func (m *InstanceList) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *InstanceList) OpsecLevel() string {
	return "low"
}

func (m *InstanceList) Authors() []string {
	return []string{"Praetorian"}
}

func (m *InstanceList) References() []string {
	return []string{
		"https://cloud.google.com/compute/docs/reference/rest/v1/instances/list",
	}
}

func (m *InstanceList) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("project", "GCP project ID", plugin.WithRequired()),
		plugin.NewParam[string]("credentials", "Path to credentials JSON file"),
	}
}

func (m *InstanceList) Run(cfg plugin.Config) ([]plugin.Result, error) {
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	// Get required parameters
	projectID, _ := cfg.Args["project"].(string)
	if projectID == "" {
		return nil, fmt.Errorf("project is required")
	}

	// Setup credentials
	var opts []option.ClientOption
	if creds, ok := cfg.Args["credentials"].(string); ok && creds != "" {
		opts = append(opts, option.WithCredentialsFile(creds))
	}

	// Create compute service
	computeService, err := compute.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute service: %w", err)
	}

	// Get zones
	zonesListCall := computeService.Zones.List(projectID)
	zonesResp, err := zonesListCall.Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list zones in project: %w", err)
	}

	// Collect results with concurrency
	var results []plugin.Result
	var mu sync.Mutex
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for _, zone := range zonesResp.Items {
		wg.Add(1)
		sem <- struct{}{}

		go func(zoneName string) {
			defer wg.Done()
			defer func() { <-sem }()

			listReq := computeService.Instances.List(projectID, zoneName)
			err := listReq.Pages(ctx, func(page *compute.InstanceList) error {
				for _, instance := range page.Items {
					result := plugin.Result{
						Data: map[string]any{
							"platform":      "gcp",
							"resource_type": "compute.googleapis.com/Instance",
							"resource_id":   fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zoneName, strconv.FormatUint(instance.Id, 10)),
							"account_ref":   projectID,
							"region":        zoneName,
							"display_name":  instance.Name,
							"properties":    postProcessComputeInstance(instance),
						},
						Metadata: map[string]any{
							"module_id": m.ID(),
							"platform":  "gcp",
							"zone":      zoneName,
						},
					}

					slog.Debug("Found GCP instance", "instance", instance.Name, "zone", zoneName)

					mu.Lock()
					results = append(results, result)
					mu.Unlock()
				}
				return nil
			})
			if err != nil {
				slog.Error("failed to list instances in zone", "error", err, "zone", zoneName)
			}
		}(zone.Name)
	}

	wg.Wait()
	return results, nil
}

// InstanceSecrets extracts secrets from compute instance metadata
type InstanceSecrets struct{}

func init() {
	plugin.Register(&InstanceSecrets{})
}

func (m *InstanceSecrets) ID() string {
	return "gcp-instance-secrets"
}

func (m *InstanceSecrets) Name() string {
	return "GCP Instance Secret Scanner"
}

func (m *InstanceSecrets) Description() string {
	return "Scans GCP compute instance metadata for potential secrets"
}

func (m *InstanceSecrets) Platform() plugin.Platform {
	return plugin.PlatformGCP
}

func (m *InstanceSecrets) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *InstanceSecrets) OpsecLevel() string {
	return "low"
}

func (m *InstanceSecrets) Authors() []string {
	return []string{"Praetorian"}
}

func (m *InstanceSecrets) References() []string {
	return []string{
		"https://cloud.google.com/compute/docs/metadata/overview",
	}
}

func (m *InstanceSecrets) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("project", "GCP project ID", plugin.WithRequired()),
		plugin.NewParam[string]("zone", "GCP zone", plugin.WithRequired()),
		plugin.NewParam[string]("instance", "Instance name", plugin.WithRequired()),
		plugin.NewParam[string]("credentials", "Path to credentials JSON file"),
	}
}

func (m *InstanceSecrets) Run(cfg plugin.Config) ([]plugin.Result, error) {
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	// Get required parameters
	projectID, _ := cfg.Args["project"].(string)
	zone, _ := cfg.Args["zone"].(string)
	instanceName, _ := cfg.Args["instance"].(string)

	if projectID == "" || zone == "" || instanceName == "" {
		return nil, fmt.Errorf("project, zone, and instance are required")
	}

	// Setup credentials
	var opts []option.ClientOption
	if creds, ok := cfg.Args["credentials"].(string); ok && creds != "" {
		opts = append(opts, option.WithCredentialsFile(creds))
	}

	// Create compute service
	computeService, err := compute.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute service: %w", err)
	}

	// Get instance
	inst, err := computeService.Instances.Get(projectID, zone, instanceName).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get instance for secrets extraction: %w", err)
	}

	// Extract metadata
	var results []plugin.Result

	if inst.Metadata != nil {
		for _, item := range inst.Metadata.Items {
			if item == nil || item.Value == nil || *item.Value == "" {
				continue
			}

			result := plugin.Result{
				Data: map[string]any{
					"content": *item.Value,
					"metadata": map[string]any{
						"key":           item.Key,
						"platform":      "gcp",
						"resource_type": "compute.googleapis.com/Instance::Metadata",
						"resource_id":   fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zone, strconv.FormatUint(inst.Id, 10)),
						"region":        zone,
						"account_id":    projectID,
					},
				},
				Metadata: map[string]any{
					"module_id":     m.ID(),
					"platform":      "gcp",
					"metadata_key":  item.Key,
					"instance_name": instanceName,
				},
			}

			results = append(results, result)
		}
	}

	return results, nil
}

// ------------------------------------------------------------------------------------------------
// Helper functions

func postProcessComputeInstance(instance *compute.Instance) map[string]any {
	properties := map[string]any{
		"name":        instance.Name,
		"id":          instance.Id,
		"description": instance.Description,
		"status":      instance.Status,
		"zone":        instance.Zone,
		"labels":      instance.Labels,
		"selfLink":    instance.SelfLink,
	}

	// Extract public IPs
	for _, networkInterface := range instance.NetworkInterfaces {
		for _, accessConfig := range networkInterface.AccessConfigs {
			if accessConfig.NatIP != "" {
				properties["publicIP"] = accessConfig.NatIP
			}
			if accessConfig.PublicPtrDomainName != "" {
				properties["publicDomain"] = accessConfig.PublicPtrDomainName
			}
		}
		for _, ipv6AccessConfig := range networkInterface.Ipv6AccessConfigs {
			if ipv6AccessConfig.ExternalIpv6 != "" {
				properties["publicIPv6"] = ipv6AccessConfig.ExternalIpv6
			}
		}
	}

	return properties
}
