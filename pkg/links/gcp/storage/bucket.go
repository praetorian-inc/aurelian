package storage

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/storage/v1"
)

// FILE INFO:
// GcpStorageBucketInfoLink
// GcpStorageBucketListLink

// get information about a specific storage bucket
type GcpStorageBucketInfoLink struct {
	*base.GcpBaseLink
	storageService *storage.Service
	ProjectId      string
}

func NewGcpStorageBucketInfoLink(configs ...cfg.Config) chain.Link {
	g := &GcpStorageBucketInfoLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpStorageBucketInfoLink) Params() []cfg.Param {
	params := append(g.GcpBaseLink.Params(),
		options.GcpProject(),
	)
	return params
}

func (g *GcpStorageBucketInfoLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.storageService, err = storage.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create storage service: %w", err)
	}
	projectId, err := cfg.As[string](g.Arg("project"))
	if err != nil {
		return fmt.Errorf("failed to get project: %w", err)
	}
	g.ProjectId = projectId
	return nil
}

func (g *GcpStorageBucketInfoLink) Process(bucketName string) error {
	bucket, err := g.storageService.Buckets.Get(bucketName).Do()
	if err != nil {
		return fmt.Errorf("failed to get bucket %s: %w", bucketName, err)
	}
	properties := linkPostProcessBucket(bucket)
	gcpBucket, err := tab.NewGCPResource(
		bucket.Name,           // resource name
		g.ProjectId,           // accountRef (project ID)
		tab.GCPResourceBucket, // resource type
		properties,            // properties
	)
	if err != nil {
		return fmt.Errorf("failed to create GCP bucket resource: %w", err)
	}
	g.Send(gcpBucket)
	return nil
}

// linkPostProcessBucket consolidates bucket processing logic for both info and list links
func linkPostProcessBucket(bucket *storage.Bucket) map[string]any {
	properties := map[string]any{
		"name":                   bucket.Name,
		"id":                     bucket.Id,
		"location":               bucket.Location,
		"selfLink":               bucket.SelfLink,
		"gsUtilURL":              fmt.Sprintf("gs://%s", bucket.Name),
		"publicURL":              fmt.Sprintf("https://storage.googleapis.com/%s", bucket.Name), // also <bucket-name>.storage.googleapis.com
		"labels":                 bucket.Labels,
		"publicAccessPrevention": bucket.IamConfiguration.PublicAccessPrevention,
	}
	if bucket.IamConfiguration != nil && bucket.IamConfiguration.PublicAccessPrevention == "inherited" {
		properties["publicAccessPrevention"] = false
	} else {
		properties["publicAccessPrevention"] = true
	}
	return properties
}

// list storage buckets within a project
type GcpStorageBucketListLink struct {
	*base.GcpBaseLink
	storageService *storage.Service
}

func NewGcpStorageBucketListLink(configs ...cfg.Config) chain.Link {
	g := &GcpStorageBucketListLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpStorageBucketListLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.storageService, err = storage.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create storage service: %w", err)
	}
	return nil
}

func (g *GcpStorageBucketListLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceProject {
		return nil
	}
	projectId := resource.Name
	listReq := g.storageService.Buckets.List(projectId)
	buckets, err := listReq.Do()
	if err != nil {
		return fmt.Errorf("failed to list buckets in project %s: %w", projectId, err)
	}
	for _, bucket := range buckets.Items {
		properties := linkPostProcessBucket(bucket)
		gcpBucket, err := tab.NewGCPResource(
			bucket.Name,           // resource name
			projectId,             // accountRef (project ID)
			tab.GCPResourceBucket, // resource type
			properties,            // properties
		)
		if err != nil {
			slog.Error("Failed to create GCP bucket resource", "error", err, "bucket", bucket.Name)
			continue
		}
		g.Send(gcpBucket)
	}
	return nil
}
