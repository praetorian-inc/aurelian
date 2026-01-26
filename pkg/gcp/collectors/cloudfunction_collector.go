package gcloudcollectors

import (
	"context"
	"fmt"
	"strings"
	"sync"

	gcptypes "github.com/praetorian-inc/nebula/pkg/types/gcp"
	"google.golang.org/api/cloudfunctions/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
)

type CloudFunctionCollector struct {
	ctx              context.Context
	clientOptions    []option.ClientOption
	functionsService *cloudfunctions.Service
	computeService   *compute.Service
}

func NewCloudFunctionCollector(ctx context.Context, clientOptions ...option.ClientOption) (*CloudFunctionCollector, error) {
	functionsService, err := cloudfunctions.NewService(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create cloud functions service: %w", err)
	}

	computeService, err := compute.NewService(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute service: %w", err)
	}

	return &CloudFunctionCollector{
		ctx:              ctx,
		clientOptions:    clientOptions,
		functionsService: functionsService,
		computeService:   computeService,
	}, nil
}

func (c *CloudFunctionCollector) Close() error {
	return nil
}

// ListInProject lists all cloud functions in a project across all regions
func (c *CloudFunctionCollector) ListInProject(ctx context.Context, projectID string) ([]*gcptypes.Resource, error) {
	// Get all regions
	regionsCall := c.computeService.Regions.List(projectID)
	regionsResp, err := regionsCall.Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list regions in project %s: %w", projectID, err)
	}

	functions := make([]*gcptypes.Resource, 0)
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
			listCall := c.functionsService.Projects.Locations.Functions.List(parent)
			resp, err := listCall.Context(ctx).Do()
			if err != nil {
				// Functions may not be enabled in all regions, so don't error
				return
			}

			for _, function := range resp.Functions {
				resource := c.functionToResource(function, projectID)
				mu.Lock()
				functions = append(functions, resource)
				mu.Unlock()
			}
		}(region.Name)
	}

	wg.Wait()
	return functions, nil
}

// GetIAMPolicy gets the IAM policy for a cloud function
func (c *CloudFunctionCollector) GetIAMPolicy(ctx context.Context, functionName string) (*gcptypes.Policies, error) {
	policy, err := c.functionsService.Projects.Locations.Functions.GetIamPolicy(functionName).OptionsRequestedPolicyVersion(3).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get IAM policy for function %s: %w", functionName, err)
	}

	allowPolicy := &gcptypes.AllowPolicy{
		ResourceURI: functionName,
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

// CollectWithPolicies lists all functions and fetches their IAM policies
func (c *CloudFunctionCollector) CollectWithPolicies(ctx context.Context, projectID, projectNumber string) ([]*gcptypes.Resource, error) {
	functions, err := c.ListInProject(ctx, projectID)
	if err != nil {
		return nil, err
	}

	parentURI := BuildProjectParentURI(projectNumber)

	for _, function := range functions {
		apiName := function.Properties["id"]
		projectIDToNumber := map[string]string{projectID: projectNumber}
		function.URI = BuildFullResourceURI("cloudfunctions.googleapis.com", apiName, projectIDToNumber)
		function.ParentURI = parentURI

		if apiName != "" {
			policies, err := c.GetIAMPolicy(ctx, apiName)
			if err != nil {
				fmt.Printf("Warning: failed to get IAM policy for %s: %v\n", function.URI, err)
				continue
			}
			function.Policies = *policies
		}
	}

	return functions, nil
}

// functionToResource converts a cloudfunctions.CloudFunction to gcptypes.Resource
func (c *CloudFunctionCollector) functionToResource(function *cloudfunctions.CloudFunction, projectID string) *gcptypes.Resource {
	// Extract location and name from function name: projects/PROJECT/locations/LOCATION/functions/NAME
	parts := strings.Split(function.Name, "/")
	location := ""
	functionName := function.Name
	if len(parts) >= 4 {
		location = parts[3]
	}
	if len(parts) >= 6 {
		functionName = parts[5]
	}

	resource := &gcptypes.Resource{
		AssetType:  "cloudfunctions.googleapis.com/CloudFunction",
		Name:       functionName,
		Location:   location,
		Properties: make(map[string]string),
	}

	resource.Properties["id"] = function.Name
	resource.Properties["runtime"] = function.Runtime
	resource.Properties["entryPoint"] = function.EntryPoint
	resource.Properties["status"] = function.Status
	if function.Description != "" {
		resource.Properties["description"] = function.Description
	}
	if function.ServiceAccountEmail != "" {
		resource.Properties["serviceAccount"] = function.ServiceAccountEmail
	}
	if function.SourceArchiveUrl != "" {
		resource.Properties["sourceArchiveUrl"] = function.SourceArchiveUrl
	}

	// Add labels
	for k, v := range function.Labels {
		resource.Properties[fmt.Sprintf("label:%s", k)] = v
	}

	return resource
}
