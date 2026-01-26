package gcloudcollectors

import (
	"context"
	"fmt"

	gcptypes "github.com/praetorian-inc/nebula/pkg/types/gcp"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

type ServiceAccountCollector struct {
	ctx           context.Context
	clientOptions []option.ClientOption
	iamService    *iam.Service
}

func NewServiceAccountCollector(ctx context.Context, clientOptions ...option.ClientOption) (*ServiceAccountCollector, error) {
	iamService, err := iam.NewService(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create IAM service: %w", err)
	}

	return &ServiceAccountCollector{
		ctx:           ctx,
		clientOptions: clientOptions,
		iamService:    iamService,
	}, nil
}

func (c *ServiceAccountCollector) Close() error {
	// google.golang.org/api services don't need explicit closing
	return nil
}

// ListInProject lists all service accounts in a project
func (c *ServiceAccountCollector) ListInProject(ctx context.Context, projectID string) ([]*gcptypes.Resource, error) {
	name := fmt.Sprintf("projects/%s", projectID)
	req := c.iamService.Projects.ServiceAccounts.List(name)

	serviceAccounts := make([]*gcptypes.Resource, 0)

	err := req.Pages(ctx, func(resp *iam.ListServiceAccountsResponse) error {
		for _, sa := range resp.Accounts {
			resource := &gcptypes.Resource{
				AssetType:  "iam.googleapis.com/ServiceAccount",
				Name:       sa.Email,
				Properties: make(map[string]string),
			}

			resource.Properties["email"] = sa.Email
			resource.Properties["uniqueId"] = sa.UniqueId
			resource.Properties["disabled"] = fmt.Sprintf("%v", sa.Disabled)
			resource.Properties["id"] = sa.Name
			if sa.Description != "" {
				resource.Properties["description"] = sa.Description
			}

			serviceAccounts = append(serviceAccounts, resource)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list service accounts in project %s: %w", projectID, err)
	}

	return serviceAccounts, nil
}

// GetIAMPolicy gets the IAM policy for a service account
func (c *ServiceAccountCollector) GetIAMPolicy(ctx context.Context, resourceName string) (*gcptypes.Policies, error) {
	policy, err := c.iamService.Projects.ServiceAccounts.GetIamPolicy(resourceName).OptionsRequestedPolicyVersion(3).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get IAM policy for %s: %w", resourceName, err)
	}

	allowPolicy := &gcptypes.AllowPolicy{
		ResourceURI: resourceName,
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
		Deny:  nil, // Service accounts don't support deny policies
	}, nil
}

// CollectWithPolicies lists all service accounts and fetches their IAM policies
func (c *ServiceAccountCollector) CollectWithPolicies(ctx context.Context, projectID, projectNumber string) ([]*gcptypes.Resource, error) {
	serviceAccounts, err := c.ListInProject(ctx, projectID)
	if err != nil {
		return nil, err
	}

	parentURI := BuildProjectParentURI(projectNumber)

	for _, sa := range serviceAccounts {
		email := sa.Properties["email"]
		sa.URI = BuildServiceAccountURI(email, projectNumber)
		sa.ParentURI = parentURI

		apiName := sa.Properties["id"]
		policies, err := c.GetIAMPolicy(ctx, apiName)
		if err != nil {
			fmt.Printf("Warning: failed to get IAM policy for %s: %v\n", sa.URI, err)
			continue
		}
		sa.Policies = *policies
	}

	return serviceAccounts, nil
}
