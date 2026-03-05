package storage

import (
	"fmt"
	"log/slog"

	"google.golang.org/api/option"
	gcsapi "google.golang.org/api/storage/v1"

	"github.com/praetorian-inc/aurelian/pkg/gcp/gcperrors"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// BucketLister enumerates Cloud Storage buckets in a GCP project.
type BucketLister struct {
	clientOptions []option.ClientOption
}

// NewBucketLister creates a BucketLister with the given client options.
func NewBucketLister(clientOptions []option.ClientOption) *BucketLister {
	return &BucketLister{clientOptions: clientOptions}
}

// List enumerates all Cloud Storage buckets for the given project.
func (l *BucketLister) List(projectID string, out *pipeline.P[output.GCPResource]) error {
	svc, err := gcsapi.NewService(nil, l.clientOptions...)
	if err != nil {
		return fmt.Errorf("creating storage client: %w", err)
	}

	call := svc.Buckets.List(projectID)
	err = call.Pages(nil, func(resp *gcsapi.Buckets) error {
		for _, bucket := range resp.Items {
			r := output.NewGCPResource(projectID, "storage.googleapis.com/Bucket", bucket.Id)
			r.DisplayName = bucket.Name
			r.Location = bucket.Location
			r.Labels = bucket.Labels
			r.Properties = map[string]any{
				"storageClass":     bucket.StorageClass,
				"iamConfiguration": bucket.IamConfiguration,
				"timeCreated":      bucket.TimeCreated,
				"versioning":       bucket.Versioning,
			}
			out.Send(r)
		}
		return nil
	})
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping storage buckets", "project", projectID, "reason", err)
			return nil
		}
		return fmt.Errorf("listing storage buckets: %w", err)
	}
	return nil
}
