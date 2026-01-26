package gcloudcollectors

import (
	"context"
	"fmt"

	gcptypes "github.com/praetorian-inc/nebula/pkg/types/gcp"
	"google.golang.org/api/deploymentmanager/v2"
	"google.golang.org/api/option"
)

type DeploymentManagerCollector struct {
	ctx          context.Context
	clientOptions []option.ClientOption
	dmService    *deploymentmanager.Service
}

func NewDeploymentManagerCollector(ctx context.Context, clientOptions ...option.ClientOption) (*DeploymentManagerCollector, error) {
	dmService, err := deploymentmanager.NewService(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create deployment manager service: %w", err)
	}

	return &DeploymentManagerCollector{
		ctx:          ctx,
		clientOptions: clientOptions,
		dmService:    dmService,
	}, nil
}

func (c *DeploymentManagerCollector) Close() error {
	return nil
}

// ListInProject lists all Deployment Manager deployments in a project
func (c *DeploymentManagerCollector) ListInProject(ctx context.Context, projectID string) ([]*gcptypes.Resource, error) {
	listCall := c.dmService.Deployments.List(projectID)
	deployments := make([]*gcptypes.Resource, 0)

	err := listCall.Pages(ctx, func(resp *deploymentmanager.DeploymentsListResponse) error {
		for _, deployment := range resp.Deployments {
			resource := c.deploymentToResource(deployment, projectID)
			deployments = append(deployments, resource)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list deployments in project %s: %w", projectID, err)
	}

	return deployments, nil
}

// GetIAMPolicy gets the IAM policy for a deployment
func (c *DeploymentManagerCollector) GetIAMPolicy(ctx context.Context, projectID, deploymentName string) (*gcptypes.Policies, error) {
	policy, err := c.dmService.Deployments.GetIamPolicy(projectID, deploymentName).OptionsRequestedPolicyVersion(3).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get IAM policy for deployment %s: %w", deploymentName, err)
	}

	allowPolicy := &gcptypes.AllowPolicy{
		ResourceURI: fmt.Sprintf("//deploymentmanager.googleapis.com/projects/%s/deployments/%s", projectID, deploymentName),
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

// CollectWithPolicies lists all deployments and fetches their IAM policies
func (c *DeploymentManagerCollector) CollectWithPolicies(ctx context.Context, projectID, projectNumber string) ([]*gcptypes.Resource, error) {
	deployments, err := c.ListInProject(ctx, projectID)
	if err != nil {
		return nil, err
	}

	parentURI := BuildProjectParentURI(projectNumber)

	for _, deployment := range deployments {
		apiName := deployment.Properties["id"]
		projectIDToNumber := map[string]string{projectID: projectNumber}
		deployment.URI = BuildFullResourceURI("deploymentmanager.googleapis.com", apiName, projectIDToNumber)
		deployment.ParentURI = parentURI

		deploymentName := deployment.Name
		if deploymentName != "" {
			policies, err := c.GetIAMPolicy(ctx, projectID, deploymentName)
			if err != nil {
				fmt.Printf("Warning: failed to get IAM policy for %s: %v\n", deployment.URI, err)
				continue
			}
			deployment.Policies = *policies
		}
	}

	return deployments, nil
}

// deploymentToResource converts a deploymentmanager.Deployment to gcptypes.Resource
func (c *DeploymentManagerCollector) deploymentToResource(deployment *deploymentmanager.Deployment, projectID string) *gcptypes.Resource {
	resource := &gcptypes.Resource{
		AssetType:  "deploymentmanager.googleapis.com/Deployment",
		Name:       deployment.Name,
		Properties: make(map[string]string),
	}

	resource.Properties["id"] = fmt.Sprintf("projects/%s/deployments/%s", projectID, deployment.Name)
	if deployment.Description != "" {
		resource.Properties["description"] = deployment.Description
	}
	if deployment.InsertTime != "" {
		resource.Properties["createTime"] = deployment.InsertTime
	}
	if deployment.Operation != nil {
		resource.Properties["state"] = deployment.Operation.Status
		if deployment.Operation.User != "" {
			resource.Properties["serviceAccount"] = deployment.Operation.User
		}
	}

	// Add labels
	for _, label := range deployment.Labels {
		resource.Properties[fmt.Sprintf("label:%s", label.Key)] = label.Value
	}

	return resource
}
