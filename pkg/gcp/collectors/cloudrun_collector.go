package gcloudcollectors

import (
	"context"
	"fmt"
	"strings"
	"sync"

	gcptypes "github.com/praetorian-inc/nebula/pkg/types/gcp"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
	"google.golang.org/api/run/v2"
)

type CloudRunCollector struct {
	ctx            context.Context
	clientOptions  []option.ClientOption
	runService     *run.Service
	computeService *compute.Service
}

func NewCloudRunCollector(ctx context.Context, clientOptions ...option.ClientOption) (*CloudRunCollector, error) {
	runService, err := run.NewService(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create cloud run service: %w", err)
	}

	computeService, err := compute.NewService(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute service: %w", err)
	}

	return &CloudRunCollector{
		ctx:            ctx,
		clientOptions:  clientOptions,
		runService:     runService,
		computeService: computeService,
	}, nil
}

func (c *CloudRunCollector) Close() error {
	return nil
}

// ListInProject lists all Cloud Run services in a project across all regions
func (c *CloudRunCollector) ListInProject(ctx context.Context, projectID string) ([]*gcptypes.Resource, error) {
	// Get all regions
	regionsCall := c.computeService.Regions.List(projectID)
	regionsResp, err := regionsCall.Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list regions in project %s: %w", projectID, err)
	}

	services := make([]*gcptypes.Resource, 0)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for _, region := range regionsResp.Items {
		wg.Add(1)
		sem <- struct{}{}
		go func(regionName string) {
			defer wg.Done()
			defer func() { <-sem }()

			parent := fmt.Sprintf("projects/%s/locations/%s", projectID, regionName)
			listCall := c.runService.Projects.Locations.Services.List(parent)
			resp, err := listCall.Context(ctx).Do()
			if err != nil {
				// Cloud Run may not be enabled in all regions
				return
			}

			for _, service := range resp.Services {
				resource := c.serviceToResource(service, projectID)
				mu.Lock()
				services = append(services, resource)
				mu.Unlock()
			}
		}(region.Name)
	}

	wg.Wait()
	return services, nil
}

// GetIAMPolicy gets the IAM policy for a Cloud Run service
func (c *CloudRunCollector) GetIAMPolicy(ctx context.Context, serviceName string) (*gcptypes.Policies, error) {
	policy, err := c.runService.Projects.Locations.Services.GetIamPolicy(serviceName).OptionsRequestedPolicyVersion(3).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get IAM policy for service %s: %w", serviceName, err)
	}

	allowPolicy := &gcptypes.AllowPolicy{
		ResourceURI: serviceName,
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
		Deny:  nil,
	}, nil
}

// CollectWithPolicies lists all Cloud Run services and fetches their IAM policies
func (c *CloudRunCollector) CollectWithPolicies(ctx context.Context, projectID, projectNumber string) ([]*gcptypes.Resource, error) {
	services, err := c.ListInProject(ctx, projectID)
	if err != nil {
		return nil, err
	}

	parentURI := BuildProjectParentURI(projectNumber)

	for _, service := range services {
		apiName := service.Properties["id"]
		projectIDToNumber := map[string]string{projectID: projectNumber}
		service.URI = BuildFullResourceURI("run.googleapis.com", apiName, projectIDToNumber)
		service.ParentURI = parentURI

		if apiName != "" {
			policies, err := c.GetIAMPolicy(ctx, apiName)
			if err != nil {
				fmt.Printf("Warning: failed to get IAM policy for %s: %v\n", service.URI, err)
				continue
			}
			service.Policies = *policies
		}
	}

	return services, nil
}

// serviceToResource converts a run.GoogleCloudRunV2Service to gcptypes.Resource
func (c *CloudRunCollector) serviceToResource(service *run.GoogleCloudRunV2Service, projectID string) *gcptypes.Resource {
	// Extract location and name from service name: projects/PROJECT/locations/LOCATION/services/NAME
	parts := strings.Split(service.Name, "/")
	location := ""
	serviceName := service.Name
	if len(parts) >= 4 {
		location = parts[3]
	}
	if len(parts) >= 6 {
		serviceName = parts[5]
	}

	resource := &gcptypes.Resource{
		AssetType:  "run.googleapis.com/Service",
		Name:       serviceName,
		Location:   location,
		Properties: make(map[string]string),
	}

	resource.Properties["id"] = service.Name
	if service.Template != nil && service.Template.ServiceAccount != "" {
		resource.Properties["serviceAccount"] = service.Template.ServiceAccount
	}
	if len(service.Urls) > 0 {
		resource.Properties["url"] = service.Urls[0]
	}

	// Add labels
	for k, v := range service.Labels {
		resource.Properties[fmt.Sprintf("label:%s", k)] = v
	}

	return resource
}
