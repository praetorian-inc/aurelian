package dnstakeover

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
	"google.golang.org/api/storage/v1"
)

// BackendBucketChecker detects GCP HTTPS Load Balancer backend buckets
// that reference non-existent GCS buckets (dangling backend bucket takeover).
type BackendBucketChecker struct {
	computeSvc *compute.Service
	storageSvc *storage.Service
}

// NewBackendBucketChecker creates a BackendBucketChecker with compute and storage clients.
func NewBackendBucketChecker(clientOptions []option.ClientOption) (*BackendBucketChecker, error) {
	ctx := context.Background()

	computeSvc, err := compute.NewService(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("creating compute client: %w", err)
	}
	storageSvc, err := storage.NewService(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("creating storage client: %w", err)
	}

	return &BackendBucketChecker{
		computeSvc: computeSvc,
		storageSvc: storageSvc,
	}, nil
}

// CheckProject scans a GCP project for backend buckets pointing to non-existent GCS buckets.
// Pipeline signature: string -> model.AurelianModel.
func (c *BackendBucketChecker) CheckProject(projectID string, out *pipeline.P[model.AurelianModel]) error {
	backendBuckets, err := c.computeSvc.BackendBuckets.List(projectID).Do()
	if err != nil {
		slog.Warn("failed to list backend buckets", "project", projectID, "error", err)
		return nil
	}

	for _, bb := range backendBuckets.Items {
		if bb.BucketName == "" {
			continue
		}

		_, err := c.storageSvc.Buckets.Get(bb.BucketName).Do()
		if err == nil {
			continue // bucket exists, not vulnerable
		}

		slog.Info("found dangling backend bucket", "project", projectID, "backend_bucket", bb.Name, "gcs_bucket", bb.BucketName)

		referencingURLMaps := c.findReferencingURLMaps(projectID, bb.SelfLink)

		risk := newBackendBucketRisk(projectID, bb.Name, bb.BucketName, bb.SelfLink, referencingURLMaps)
		out.Send(risk)
	}

	return nil
}

// findReferencingURLMaps returns the names of URL maps that reference the given backend bucket.
func (c *BackendBucketChecker) findReferencingURLMaps(projectID, backendBucketSelfLink string) []string {
	urlMaps, err := c.computeSvc.UrlMaps.List(projectID).Do()
	if err != nil {
		slog.Warn("failed to list url maps", "project", projectID, "error", err)
		return nil
	}

	var refs []string
	for _, um := range urlMaps.Items {
		if referencesBackendBucket(um, backendBucketSelfLink) {
			refs = append(refs, um.Name)
		}
	}
	return refs
}

// referencesBackendBucket checks if a URL map references the given backend bucket self link.
func referencesBackendBucket(um *compute.UrlMap, selfLink string) bool {
	if um.DefaultService == selfLink {
		return true
	}
	for _, pm := range um.PathMatchers {
		if pm.DefaultService == selfLink {
			return true
		}
		for _, pr := range pm.PathRules {
			if pr.Service == selfLink {
				return true
			}
		}
	}
	for _, hr := range um.HostRules {
		_ = hr // host rules reference path matchers by name, not directly
	}
	return false
}

// newBackendBucketRisk builds an AurelianRisk for a dangling backend bucket finding.
func newBackendBucketRisk(projectID, backendBucketName, gcsBucketName, selfLink string, referencingURLMaps []string) output.AurelianRisk {
	severity := output.RiskSeverityHigh
	if len(referencingURLMaps) > 0 {
		severity = output.RiskSeverityCritical
	}

	description := fmt.Sprintf(
		"Backend bucket %q in project %s references non-existent GCS bucket %q. "+
			"An attacker could create this bucket to serve malicious content through the load balancer.",
		backendBucketName, projectID, gcsBucketName,
	)

	remediation := fmt.Sprintf(
		"1. Create the GCS bucket %q in your project to reclaim ownership, OR\n"+
			"2. Delete the backend bucket %q if no longer needed, OR\n"+
			"3. Update the backend bucket to reference an existing GCS bucket.",
		gcsBucketName, backendBucketName,
	)

	resourceID := selfLink
	if resourceID == "" {
		resourceID = fmt.Sprintf("projects/%s/global/backendBuckets/%s", projectID, backendBucketName)
	}

	ctx, _ := json.Marshal(map[string]any{
		"project_id":           projectID,
		"backend_bucket_name":  backendBucketName,
		"gcs_bucket_name":      gcsBucketName,
		"referencing_url_maps": referencingURLMaps,
		"description":          description,
		"remediation":          remediation,
	})

	return output.AurelianRisk{
		Name:               "gcp-lb-backend-bucket-takeover",
		Severity:           severity,
		ImpactedResourceID: resourceID,
		DeduplicationID:    fmt.Sprintf("lb-backend-takeover:%s:%s", projectID, backendBucketName),
		Context:            ctx,
	}
}
