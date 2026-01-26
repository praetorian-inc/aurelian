package gcloudcollectors

import (
	"context"
	"fmt"

	gcptypes "github.com/praetorian-inc/nebula/pkg/types/gcp"
	"google.golang.org/api/option"
	"google.golang.org/api/storage/v1"
)

type StorageBucketCollector struct {
	ctx            context.Context
	clientOptions  []option.ClientOption
	storageService *storage.Service
}

func NewStorageBucketCollector(ctx context.Context, clientOptions ...option.ClientOption) (*StorageBucketCollector, error) {
	storageService, err := storage.NewService(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage service: %w", err)
	}

	return &StorageBucketCollector{
		ctx:            ctx,
		clientOptions:  clientOptions,
		storageService: storageService,
	}, nil
}

func (c *StorageBucketCollector) Close() error {
	return nil
}

// ListInProject lists all storage buckets in a project
func (c *StorageBucketCollector) ListInProject(ctx context.Context, projectID string) ([]*gcptypes.Resource, error) {
	listCall := c.storageService.Buckets.List(projectID)
	buckets := make([]*gcptypes.Resource, 0)

	err := listCall.Pages(ctx, func(resp *storage.Buckets) error {
		for _, bucket := range resp.Items {
			resource := c.bucketToResource(bucket, projectID)
			buckets = append(buckets, resource)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list buckets in project %s: %w", projectID, err)
	}

	return buckets, nil
}

// GetIAMPolicy gets the IAM policy for a storage bucket
func (c *StorageBucketCollector) GetIAMPolicy(ctx context.Context, bucketName string) (*gcptypes.Policies, error) {
	policy, err := c.storageService.Buckets.GetIamPolicy(bucketName).OptionsRequestedPolicyVersion(3).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get IAM policy for bucket %s: %w", bucketName, err)
	}

	allowPolicy := &gcptypes.AllowPolicy{
		ResourceURI: fmt.Sprintf("//storage.googleapis.com/%s", bucketName),
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

// CollectWithPolicies lists all buckets and fetches their IAM policies
func (c *StorageBucketCollector) CollectWithPolicies(ctx context.Context, projectID, projectNumber string) ([]*gcptypes.Resource, error) {
	buckets, err := c.ListInProject(ctx, projectID)
	if err != nil {
		return nil, err
	}

	parentURI := BuildProjectParentURI(projectNumber)

	for _, bucket := range buckets {
		apiName := bucket.Properties["id"]
		projectIDToNumber := map[string]string{projectID: projectNumber}
		bucket.URI = BuildFullResourceURI("storage.googleapis.com", apiName, projectIDToNumber)
		bucket.ParentURI = parentURI

		bucketName := bucket.Name
		if bucketName != "" {
			policies, err := c.GetIAMPolicy(ctx, bucketName)
			if err != nil {
				fmt.Printf("Warning: failed to get IAM policy for %s: %v\n", bucket.URI, err)
				continue
			}
			bucket.Policies = *policies
		}
	}

	return buckets, nil
}

// bucketToResource converts a storage.Bucket to gcptypes.Resource
func (c *StorageBucketCollector) bucketToResource(bucket *storage.Bucket, projectID string) *gcptypes.Resource {
	resource := &gcptypes.Resource{
		AssetType:  "storage.googleapis.com/Bucket",
		Name:       bucket.Name,
		Location:   bucket.Location,
		Properties: make(map[string]string),
	}

	resource.Properties["id"] = fmt.Sprintf("projects/%s/buckets/%s", projectID, bucket.Name)
	resource.Properties["storageClass"] = bucket.StorageClass
	if bucket.Versioning != nil {
		resource.Properties["versioning"] = fmt.Sprintf("%v", bucket.Versioning.Enabled)
	}

	// Add labels
	for k, v := range bucket.Labels {
		resource.Properties[fmt.Sprintf("label:%s", k)] = v
	}

	return resource
}
