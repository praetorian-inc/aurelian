package applications

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"

	computeapi "google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
	runapi "google.golang.org/api/run/v2"

	"github.com/praetorian-inc/aurelian/pkg/gcp/gcperrors"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// CloudRunLister enumerates Cloud Run services in a GCP project.
type CloudRunLister struct {
	clientOptions []option.ClientOption
}

// NewCloudRunLister creates a CloudRunLister with the given client options.
func NewCloudRunLister(clientOptions []option.ClientOption) *CloudRunLister {
	return &CloudRunLister{clientOptions: clientOptions}
}

// List enumerates all Cloud Run services across all locations for the given project.
func (l *CloudRunLister) List(projectID string, out *pipeline.P[output.GCPResource]) error {
	svc, err := runapi.NewService(nil, l.clientOptions...)
	if err != nil {
		return fmt.Errorf("creating cloud run client: %w", err)
	}

	// Use compute API to list regions for fan-out.
	computeSvc, err := computeapi.NewService(nil, l.clientOptions...)
	if err != nil {
		return fmt.Errorf("creating compute client for regions: %w", err)
	}

	var locations []string
	err = computeSvc.Regions.List(projectID).Pages(nil, func(resp *computeapi.RegionList) error {
		for _, region := range resp.Items {
			locations = append(locations, "projects/"+projectID+"/locations/"+region.Name)
		}
		return nil
	})
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping cloud run services", "project", projectID, "reason", err)
			return nil
		}
		return fmt.Errorf("listing regions for cloud run: %w", err)
	}

	// Fan out per location with a semaphore.
	var (
		wg       sync.WaitGroup
		sem      = make(chan struct{}, 10)
		mu       sync.Mutex
		firstErr error
	)

	for _, location := range locations {
		wg.Add(1)
		sem <- struct{}{}
		go func(locationName string) {
			defer wg.Done()
			defer func() { <-sem }()

			err := svc.Projects.Locations.Services.List(locationName).Pages(nil, func(resp *runapi.GoogleCloudRunV2ListServicesResponse) error {
				for _, service := range resp.Services {
					r := output.NewGCPResource(projectID, "run.googleapis.com/Service", service.Name)
					r.DisplayName = service.Name
					r.Labels = service.Labels

					if service.Uri != "" {
						r.URLs = []string{service.Uri}
					}

					props := map[string]any{}

					// Detect Gen2 Cloud Functions.
					managedBy, hasManagedBy := service.Labels["goog-managed-by"]
					if (hasManagedBy && managedBy == "cloudfunctions") ||
						(service.Uri != "" && strings.Contains(service.Uri, "cloudfunctions.net")) {
						props["isGen2CloudFunction"] = true
					}

					r.Properties = props
					out.Send(r)
				}
				return nil
			})
			if err != nil {
				if gcperrors.ShouldSkip(err) {
					slog.Debug("skipping cloud run services in location", "project", projectID, "location", locationName, "reason", err)
					return
				}
				mu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("listing cloud run services in %s: %w", locationName, err)
				}
				mu.Unlock()
			}
		}(location)
	}

	wg.Wait()
	return firstErr
}
