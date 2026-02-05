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
	"google.golang.org/api/option"
)

func init() {
	plugin.Register(&GCPListInstancesModule{})
}

// GCPListInstancesModule lists all compute instances in a GCP project
type GCPListInstancesModule struct{}

func (m *GCPListInstancesModule) ID() string {
	return "instances-list"
}

func (m *GCPListInstancesModule) Name() string {
	return "GCP List Instances"
}

func (m *GCPListInstancesModule) Description() string {
	return "List all instances in a GCP project."
}

func (m *GCPListInstancesModule) Platform() plugin.Platform {
	return plugin.PlatformGCP
}

func (m *GCPListInstancesModule) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *GCPListInstancesModule) OpsecLevel() string {
	return "moderate"
}

func (m *GCPListInstancesModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *GCPListInstancesModule) References() []string {
	return []string{}
}

func (m *GCPListInstancesModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "project",
			Description: "GCP project ID",
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

func (m *GCPListInstancesModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Get project parameter
	projectID, ok := cfg.Args["project"].(string)
	if !ok || projectID == "" {
		return nil, fmt.Errorf("project parameter is required")
	}

	// Get optional credentials file parameter
	credsFile, _ := cfg.Args["creds-file"].(string)

	// Setup GCP client options
	var clientOptions []option.ClientOption
	if credsFile != "" {
		clientOptions = append(clientOptions, option.WithCredentialsFile(credsFile))
	} else {
		// Attempt to use application default credentials
		_, err := google.FindDefaultCredentials(cfg.Context)
		if err != nil {
			return nil, fmt.Errorf("cannot find default credentials (use --creds-file): %w", err)
		}
	}

	// Create resource manager service to get project info
	resourceManagerService, err := cloudresourcemanager.NewService(cfg.Context, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource manager service: %w", err)
	}

	// Get project info
	project, err := resourceManagerService.Projects.Get(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get project %s: %w", projectID, err)
	}

	gcpProject := &output.CloudResource{
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

	// Create compute service
	computeService, err := compute.NewService(cfg.Context, clientOptions...)
	if err != nil {
		return nil, utils.HandleGcpError(err, "failed to create compute service")
	}

	// List zones in the project
	zonesListCall := computeService.Zones.List(projectID)
	zonesResp, err := zonesListCall.Do()
	if err != nil {
		return nil, utils.HandleGcpError(err, "failed to list zones in project")
	}

	// Collect all instances
	var instances []*output.CloudResource
	var mu sync.Mutex
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	// List instances in each zone concurrently
	for _, zone := range zonesResp.Items {
		wg.Add(1)
		sem <- struct{}{}
		go func(zoneName string) {
			defer wg.Done()
			defer func() { <-sem }()

			listReq := computeService.Instances.List(projectID, zoneName)
			err := listReq.Pages(context.Background(), func(page *compute.InstanceList) error {
				for _, instance := range page.Items {
					gcpInstance := &output.CloudResource{
						Platform:     "gcp",
						ResourceType: "compute.googleapis.com/Instance",
						ResourceID:   fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zoneName, strconv.FormatUint(instance.Id, 10)),
						AccountRef:   projectID,
						Region:       zoneName,
						DisplayName:  instance.Name,
						Properties:   postProcessComputeInstance(instance),
					}
					slog.Debug("Found GCP instance", "instance", gcpInstance.DisplayName)

					mu.Lock()
					instances = append(instances, gcpInstance)
					mu.Unlock()
				}
				return nil
			})
			if handledErr := utils.HandleGcpError(err, "failed to list instances in zone"); handledErr != nil {
				slog.Error("error listing instances", "error", handledErr, "zone", zoneName)
			}
		}(zone.Name)
	}
	wg.Wait()

	// Return results - project first, then all instances
	results := []plugin.Result{
		{
			Data:     gcpProject,
			Metadata: map[string]any{
				"module":   "instances-list",
				"platform": "gcp",
				"type":     "project",
			},
		},
	}

	for _, instance := range instances {
		results = append(results, plugin.Result{
			Data:     instance,
			Metadata: map[string]any{
				"module":   "instances-list",
				"platform": "gcp",
				"type":     "instance",
			},
		})
	}

	return results, nil
}

// postProcessComputeInstance extracts relevant properties from a compute instance
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

	// Extract public IPs and domains
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
