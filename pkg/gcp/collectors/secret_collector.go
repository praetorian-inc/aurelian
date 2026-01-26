package gcloudcollectors

import (
	"context"
	"fmt"
	"strings"

	gcptypes "github.com/praetorian-inc/nebula/pkg/types/gcp"
	"google.golang.org/api/option"
	"google.golang.org/api/secretmanager/v1"
)

type SecretCollector struct {
	ctx           context.Context
	clientOptions []option.ClientOption
	secretService *secretmanager.Service
}

func NewSecretCollector(ctx context.Context, clientOptions ...option.ClientOption) (*SecretCollector, error) {
	secretService, err := secretmanager.NewService(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret manager service: %w", err)
	}

	return &SecretCollector{
		ctx:           ctx,
		clientOptions:  clientOptions,
		secretService: secretService,
	}, nil
}

func (c *SecretCollector) Close() error {
	return nil
}

// ListInProject lists all secrets in a project
func (c *SecretCollector) ListInProject(ctx context.Context, projectID string) ([]*gcptypes.Resource, error) {
	parent := fmt.Sprintf("projects/%s", projectID)
	listCall := c.secretService.Projects.Secrets.List(parent)
	secrets := make([]*gcptypes.Resource, 0)

	err := listCall.Pages(ctx, func(resp *secretmanager.ListSecretsResponse) error {
		for _, secret := range resp.Secrets {
			resource := c.secretToResource(secret, projectID)
			secrets = append(secrets, resource)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list secrets in project %s: %w", projectID, err)
	}

	return secrets, nil
}

// GetIAMPolicy gets the IAM policy for a secret
func (c *SecretCollector) GetIAMPolicy(ctx context.Context, secretName string) (*gcptypes.Policies, error) {
	policy, err := c.secretService.Projects.Secrets.GetIamPolicy(secretName).OptionsRequestedPolicyVersion(3).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get IAM policy for secret %s: %w", secretName, err)
	}

	allowPolicy := &gcptypes.AllowPolicy{
		ResourceURI: secretName,
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

// CollectWithPolicies lists all secrets and fetches their IAM policies
func (c *SecretCollector) CollectWithPolicies(ctx context.Context, projectID, projectNumber string) ([]*gcptypes.Resource, error) {
	secrets, err := c.ListInProject(ctx, projectID)
	if err != nil {
		return nil, err
	}

	parentURI := BuildProjectParentURI(projectNumber)

	for _, secret := range secrets {
		apiName := secret.Properties["id"]
		projectIDToNumber := map[string]string{projectID: projectNumber}
		secret.URI = BuildFullResourceURI("secretmanager.googleapis.com", apiName, projectIDToNumber)
		secret.ParentURI = parentURI

		if apiName != "" {
			policies, err := c.GetIAMPolicy(ctx, apiName)
			if err != nil {
				fmt.Printf("Warning: failed to get IAM policy for %s: %v\n", secret.URI, err)
				continue
			}
			secret.Policies = *policies
		}
	}

	return secrets, nil
}

// secretToResource converts a secretmanager.Secret to gcptypes.Resource
func (c *SecretCollector) secretToResource(secret *secretmanager.Secret, projectID string) *gcptypes.Resource {
	// Extract secret name from full path: projects/PROJECT/secrets/SECRET
	parts := strings.Split(secret.Name, "/")
	secretName := secret.Name
	if len(parts) >= 4 {
		secretName = parts[3]
	}

	resource := &gcptypes.Resource{
		AssetType:  "secretmanager.googleapis.com/Secret",
		Name:       secretName,
		Properties: make(map[string]string),
	}

	resource.Properties["id"] = secret.Name
	resource.Properties["createTime"] = secret.CreateTime
	if secret.Replication != nil {
		if secret.Replication.Automatic != nil {
			resource.Properties["replication"] = "automatic"
		} else if secret.Replication.UserManaged != nil {
			resource.Properties["replication"] = "user-managed"
		}
	}

	// Add labels
	for k, v := range secret.Labels {
		resource.Properties[fmt.Sprintf("label:%s", k)] = v
	}

	return resource
}
