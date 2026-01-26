package gcloudcollectors

import (
	"context"
	"fmt"
	"strings"
	"sync"

	gcptypes "github.com/praetorian-inc/nebula/pkg/types/gcp"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
)

type ComputeInstanceCollector struct {
	ctx            context.Context
	clientOptions  []option.ClientOption
	computeService *compute.Service
}

func NewComputeInstanceCollector(ctx context.Context, clientOptions ...option.ClientOption) (*ComputeInstanceCollector, error) {
	computeService, err := compute.NewService(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute service: %w", err)
	}

	return &ComputeInstanceCollector{
		ctx:            ctx,
		clientOptions:  clientOptions,
		computeService: computeService,
	}, nil
}

func (c *ComputeInstanceCollector) Close() error {
	// google.golang.org/api services don't need explicit closing
	return nil
}

// ListInProject lists all instances in a project across all zones
func (c *ComputeInstanceCollector) ListInProject(ctx context.Context, projectID string) ([]*gcptypes.Resource, error) {
	// First, get all zones
	zonesCall := c.computeService.Zones.List(projectID)
	zonesResp, err := zonesCall.Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list zones in project %s: %w", projectID, err)
	}

	instances := make([]*gcptypes.Resource, 0)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // Limit concurrency

	for _, zone := range zonesResp.Items {
		wg.Add(1)
		sem <- struct{}{}
		go func(zoneName string) {
			defer wg.Done()
			defer func() { <-sem }()

			listReq := c.computeService.Instances.List(projectID, zoneName)
			err := listReq.Pages(ctx, func(page *compute.InstanceList) error {
				for _, instance := range page.Items {
					resource := c.instanceToResource(instance, projectID)
					mu.Lock()
					instances = append(instances, resource)
					mu.Unlock()
				}
				return nil
			})
			if err != nil {
				fmt.Printf("Warning: failed to list instances in zone %s: %v\n", zoneName, err)
			}
		}(zone.Name)
	}

	wg.Wait()
	return instances, nil
}

// GetInstance gets a specific instance
func (c *ComputeInstanceCollector) GetInstance(ctx context.Context, projectID, zone, name string) (*gcptypes.Resource, error) {
	instance, err := c.computeService.Instances.Get(projectID, zone, name).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get instance %s in zone %s: %w", name, zone, err)
	}

	return c.instanceToResource(instance, projectID), nil
}

// GetIAMPolicy gets the IAM policy for an instance
func (c *ComputeInstanceCollector) GetIAMPolicy(ctx context.Context, projectID, zone, name string) (*gcptypes.Policies, error) {
	policy, err := c.computeService.Instances.GetIamPolicy(projectID, zone, name).OptionsRequestedPolicyVersion(3).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get IAM policy for instance %s: %w", name, err)
	}

	allowPolicy := &gcptypes.AllowPolicy{
		ResourceURI: fmt.Sprintf("//compute.googleapis.com/projects/%s/zones/%s/instances/%s", projectID, zone, name),
		Version:     int(policy.Version),
		Etag:        policy.Etag,
		Bindings:    make([]gcptypes.AllowBinding, 0),
	}

	for _, binding := range policy.Bindings {
		allowBinding := gcptypes.AllowBinding{
			Role:    binding.Role,
			Members: binding.Members,
		}

		if binding.Condition != nil {
			allowBinding.Condition = &gcptypes.Condition{
				Title:       binding.Condition.Title,
				Description: binding.Condition.Description,
				Expression:  binding.Condition.Expression,
			}
		}

		allowPolicy.Bindings = append(allowPolicy.Bindings, allowBinding)
	}

	return &gcptypes.Policies{
		Allow: allowPolicy,
		Deny:  nil, // Compute instances don't support deny policies
	}, nil
}

// CollectWithPolicies lists all instances and fetches their IAM policies
func (c *ComputeInstanceCollector) CollectWithPolicies(ctx context.Context, projectID, projectNumber string) ([]*gcptypes.Resource, error) {
	instances, err := c.ListInProject(ctx, projectID)
	if err != nil {
		return nil, err
	}

	parentURI := BuildProjectParentURI(projectNumber)

	for _, instance := range instances {
		apiName := instance.Properties["id"]
		projectIDToNumber := map[string]string{projectID: projectNumber}
		instance.URI = BuildFullResourceURI("compute.googleapis.com", apiName, projectIDToNumber)
		instance.ParentURI = parentURI

		zone := instance.Properties["zone"]
		name := instance.Name
		if zone != "" && name != "" {
			policies, err := c.GetIAMPolicy(ctx, projectID, zone, name)
			if err != nil {
				fmt.Printf("Warning: failed to get IAM policy for %s: %v\n", instance.URI, err)
				continue
			}
			instance.Policies = *policies
		}
	}

	return instances, nil
}

// instanceToResource converts a compute.Instance to gcptypes.Resource
func (c *ComputeInstanceCollector) instanceToResource(instance *compute.Instance, projectID string) *gcptypes.Resource {
	// Extract zone name from zone URL
	zoneParts := strings.Split(instance.Zone, "/")
	zone := zoneParts[len(zoneParts)-1]

	resource := &gcptypes.Resource{
		AssetType:  "compute.googleapis.com/Instance",
		Name:       instance.Name,
		Location:   zone,
		Properties: make(map[string]string),
	}

	resource.Properties["id"] = fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zone, instance.Name)
	resource.Properties["zone"] = zone
	resource.Properties["status"] = instance.Status
	resource.Properties["machineType"] = instance.MachineType
	if instance.Description != "" {
		resource.Properties["description"] = instance.Description
	}

	// Extract service account
	if len(instance.ServiceAccounts) > 0 {
		resource.Properties["serviceAccount"] = instance.ServiceAccounts[0].Email
	}

	// Add instance tags
	if instance.Tags != nil && len(instance.Tags.Items) > 0 {
		resource.Properties["instanceTags"] = strings.Join(instance.Tags.Items, ",")
	}

	// Add labels
	for k, v := range instance.Labels {
		resource.Properties[fmt.Sprintf("label:%s", k)] = v
	}

	return resource
}
