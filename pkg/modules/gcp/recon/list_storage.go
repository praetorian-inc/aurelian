package recon

import (
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"google.golang.org/api/option"
	"google.golang.org/api/sqladmin/v1"
	"google.golang.org/api/storage/v1"
)

func init() {
	plugin.Register(&GCPListBucketsModule{})
	plugin.Register(&GCPListSQLInstancesModule{})
}

// GCPListBucketsModule lists all storage buckets in a GCP project
type GCPListBucketsModule struct{}

func (m *GCPListBucketsModule) ID() string {
	return "buckets-list"
}

func (m *GCPListBucketsModule) Name() string {
	return "GCP List Buckets"
}

func (m *GCPListBucketsModule) Description() string {
	return "List all storage buckets in a GCP project."
}

func (m *GCPListBucketsModule) Platform() plugin.Platform {
	return plugin.PlatformGCP
}

func (m *GCPListBucketsModule) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *GCPListBucketsModule) OpsecLevel() string {
	return "moderate"
}

func (m *GCPListBucketsModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *GCPListBucketsModule) References() []string {
	return []string{}
}

func (m *GCPListBucketsModule) Parameters() []plugin.Parameter {
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

func (m *GCPListBucketsModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Get required project parameter
	projectID, ok := cfg.Args["project"].(string)
	if !ok || projectID == "" {
		return nil, fmt.Errorf("project parameter is required")
	}

	// Get optional credentials file
	credsFile, _ := cfg.Args["creds-file"].(string)

	// Setup GCP client options
	var clientOptions []option.ClientOption
	if credsFile != "" {
		clientOptions = append(clientOptions, option.WithCredentialsFile(credsFile))
	}

	// Create Storage service
	storageService, err := storage.NewService(cfg.Context, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage service: %w", err)
	}

	// Create project resource first
	projectResource := &output.CloudResource{
		Platform:     "gcp",
		ResourceType: "cloudresourcemanager.googleapis.com/Project",
		ResourceID:   fmt.Sprintf("projects/%s", projectID),
		AccountRef:   projectID,
		DisplayName:  projectID,
	}

	results := []plugin.Result{
		{
			Data: projectResource,
			Metadata: map[string]any{
				"module":   "buckets-list",
				"platform": "gcp",
				"type":     "project",
			},
		},
	}

	// List all buckets in the project
	listCall := storageService.Buckets.List(projectID)

	err = listCall.Pages(cfg.Context, func(page *storage.Buckets) error {
		for _, bucket := range page.Items {
			bucketResource := &output.CloudResource{
				Platform:     "gcp",
				ResourceType: "storage.googleapis.com/Bucket",
				ResourceID:   fmt.Sprintf("projects/%s/buckets/%s", projectID, bucket.Name),
				AccountRef:   projectID,
				DisplayName:  bucket.Name,
				Properties:   postProcessBucket(bucket),
			}

			results = append(results, plugin.Result{
				Data: bucketResource,
				Metadata: map[string]any{
					"module":   "buckets-list",
					"platform": "gcp",
					"type":     "bucket",
				},
			})
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list buckets: %w", err)
	}

	return results, nil
}

// postProcessBucket extracts relevant properties from a storage.Bucket
func postProcessBucket(bucket *storage.Bucket) map[string]any {
	properties := map[string]any{
		"name":         bucket.Name,
		"location":     bucket.Location,
		"storageClass": bucket.StorageClass,
		"timeCreated":  bucket.TimeCreated,
		"updated":      bucket.Updated,
		"labels":       bucket.Labels,
	}

	if bucket.Versioning != nil {
		properties["versioning"] = bucket.Versioning.Enabled
	}

	if bucket.Encryption != nil {
		properties["encryption"] = map[string]any{
			"defaultKmsKeyName": bucket.Encryption.DefaultKmsKeyName,
		}
	}

	if bucket.Lifecycle != nil && len(bucket.Lifecycle.Rule) > 0 {
		properties["lifecycleRules"] = len(bucket.Lifecycle.Rule)
	}

	return properties
}

// GCPListSQLInstancesModule lists all SQL instances in a GCP project
type GCPListSQLInstancesModule struct{}

func (m *GCPListSQLInstancesModule) ID() string {
	return "sql-instances-list"
}

func (m *GCPListSQLInstancesModule) Name() string {
	return "GCP List SQL Instances"
}

func (m *GCPListSQLInstancesModule) Description() string {
	return "List all SQL instances in a GCP project."
}

func (m *GCPListSQLInstancesModule) Platform() plugin.Platform {
	return plugin.PlatformGCP
}

func (m *GCPListSQLInstancesModule) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *GCPListSQLInstancesModule) OpsecLevel() string {
	return "moderate"
}

func (m *GCPListSQLInstancesModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *GCPListSQLInstancesModule) References() []string {
	return []string{}
}

func (m *GCPListSQLInstancesModule) Parameters() []plugin.Parameter {
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

func (m *GCPListSQLInstancesModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Get required project parameter
	projectID, ok := cfg.Args["project"].(string)
	if !ok || projectID == "" {
		return nil, fmt.Errorf("project parameter is required")
	}

	// Get optional credentials file
	credsFile, _ := cfg.Args["creds-file"].(string)

	// Setup GCP client options
	var clientOptions []option.ClientOption
	if credsFile != "" {
		clientOptions = append(clientOptions, option.WithCredentialsFile(credsFile))
	}

	// Create SQL Admin service
	sqlService, err := sqladmin.NewService(cfg.Context, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create sql admin service: %w", err)
	}

	// Create project resource first
	projectResource := &output.CloudResource{
		Platform:     "gcp",
		ResourceType: "cloudresourcemanager.googleapis.com/Project",
		ResourceID:   fmt.Sprintf("projects/%s", projectID),
		AccountRef:   projectID,
		DisplayName:  projectID,
	}

	results := []plugin.Result{
		{
			Data: projectResource,
			Metadata: map[string]any{
				"module":   "sql-instances-list",
				"platform": "gcp",
				"type":     "project",
			},
		},
	}

	// List all SQL instances in the project
	listCall := sqlService.Instances.List(projectID)

	resp, err := listCall.Context(cfg.Context).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list SQL instances: %w", err)
	}

	for _, instance := range resp.Items {
		instanceResource := &output.CloudResource{
			Platform:     "gcp",
			ResourceType: "sqladmin.googleapis.com/Instance",
			ResourceID:   fmt.Sprintf("projects/%s/instances/%s", projectID, instance.Name),
			AccountRef:   projectID,
			DisplayName:  instance.Name,
			Properties:   postProcessSQLInstance(instance),
		}

		results = append(results, plugin.Result{
			Data: instanceResource,
			Metadata: map[string]any{
				"module":   "sql-instances-list",
				"platform": "gcp",
				"type":     "sql-instance",
			},
		})
	}

	return results, nil
}

// postProcessSQLInstance extracts relevant properties from a sqladmin.DatabaseInstance
func postProcessSQLInstance(instance *sqladmin.DatabaseInstance) map[string]any {
	properties := map[string]any{
		"name":            instance.Name,
		"databaseVersion": instance.DatabaseVersion,
		"state":           instance.State,
		"region":          instance.Region,
		"gceZone":         instance.GceZone,
	}

	if instance.Settings != nil {
		settings := map[string]any{
			"tier":              instance.Settings.Tier,
			"availabilityType":  instance.Settings.AvailabilityType,
			"pricingPlan":       instance.Settings.PricingPlan,
			"activationPolicy":  instance.Settings.ActivationPolicy,
			"storageAutoResize": instance.Settings.StorageAutoResize,
		}

		if instance.Settings.IpConfiguration != nil {
			settings["ipConfiguration"] = map[string]any{
				"requireSsl":         instance.Settings.IpConfiguration.RequireSsl,
				"privateNetwork":     instance.Settings.IpConfiguration.PrivateNetwork,
				"ipv4Enabled":        instance.Settings.IpConfiguration.Ipv4Enabled,
				"authorizedNetworks": len(instance.Settings.IpConfiguration.AuthorizedNetworks),
			}
		}

		if instance.Settings.BackupConfiguration != nil {
			settings["backupConfiguration"] = map[string]any{
				"enabled":                    instance.Settings.BackupConfiguration.Enabled,
				"pointInTimeRecoveryEnabled": instance.Settings.BackupConfiguration.PointInTimeRecoveryEnabled,
			}
		}

		properties["settings"] = settings
	}

	if len(instance.IpAddresses) > 0 {
		ipAddresses := make([]string, 0, len(instance.IpAddresses))
		for _, ip := range instance.IpAddresses {
			ipAddresses = append(ipAddresses, ip.IpAddress)
		}
		properties["ipAddresses"] = ipAddresses
	}

	return properties
}
