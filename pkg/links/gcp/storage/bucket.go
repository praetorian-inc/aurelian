package storage

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/utils"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/storage/v1"
)

// FILE INFO:
// GcpStorageBucketInfoLink - get info of a single storage bucket, Process(bucketName string); needs project
// GcpStorageBucketListLink - list all storage buckets in a project, Process(resource tab.GCPResource); needs project

type GcpStorageBucketInfoLink struct {
	*base.GcpBaseLink
	storageService *storage.Service
	ProjectId      string
}

// creates a link to get info of a single storage bucket
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
		return utils.HandleGcpError(err, "failed to get bucket")
	}
	gcpBucket, err := tab.NewGCPResource(
		bucket.Name,                   // resource name (bucket name)
		g.ProjectId,                   // accountRef (project ID)
		tab.GCPResourceBucket,         // resource type
		linkPostProcessBucket(bucket), // properties
	)
	if err != nil {
		slog.Error("Failed to create GCP bucket resource", "error", err, "bucket", bucket.Name)
		return err
	}
	g.Send(gcpBucket)
	return nil
}

type GcpStorageBucketListLink struct {
	*base.GcpBaseLink
	storageService *storage.Service
}

// creates a link to list all storage buckets in a project
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
		return utils.HandleGcpError(err, "failed to list buckets in project")
	}
	for _, bucket := range buckets.Items {
		gcpBucket, err := tab.NewGCPResource(
			bucket.Name,                   // resource name (bucket name)
			projectId,                     // accountRef (project ID)
			tab.GCPResourceBucket,         // resource type
			linkPostProcessBucket(bucket), // properties
		)
		if err != nil {
			slog.Error("Failed to create GCP bucket resource", "error", err, "bucket", bucket.Name)
			continue
		}
		g.Send(gcpBucket)
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------------------------
// helper functions

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
