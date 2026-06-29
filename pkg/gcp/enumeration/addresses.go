package enumeration

import (
	"context"
	"fmt"
	"log/slog"

	"golang.org/x/sync/errgroup"
	computeapi "google.golang.org/api/compute/v1"
	"google.golang.org/api/option"

	"github.com/praetorian-inc/aurelian/pkg/gcp/gcperrors"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// AddressLister enumerates global and regional IP addresses in a GCP project.
type AddressLister struct {
	clientOptions []option.ClientOption
}

// NewAddressLister creates an AddressLister with the given client options.
func NewAddressLister(clientOptions []option.ClientOption) *AddressLister {
	return &AddressLister{clientOptions: clientOptions}
}

// List enumerates all addresses (global and regional) for the given project.
func (l *AddressLister) List(projectID string, out *pipeline.P[output.GCPResource]) error {
	svc, err := computeapi.NewService(context.Background(), l.clientOptions...)
	if err != nil {
		return fmt.Errorf("creating compute client: %w", err)
	}

	// Global addresses.
	err = svc.GlobalAddresses.List(projectID).Pages(context.Background(), func(resp *computeapi.AddressList) error {
		for _, addr := range resp.Items {
			sendAddress(projectID, "compute.googleapis.com/GlobalAddress", "global", addr, out)
		}
		return nil
	})
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping global addresses", "project", projectID, "reason", err)
		} else {
			return fmt.Errorf("listing global addresses: %w", err)
		}
	}

	// List regions for regional addresses.
	var regions []string
	err = svc.Regions.List(projectID).Pages(context.Background(), func(resp *computeapi.RegionList) error {
		for _, region := range resp.Items {
			regions = append(regions, region.Name)
		}
		return nil
	})
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping regional addresses", "project", projectID, "reason", err)
			return nil
		}
		return fmt.Errorf("listing regions: %w", err)
	}

	// Fan out per region with bounded concurrency.
	g := errgroup.Group{}
	g.SetLimit(10)

	for _, region := range regions {
		g.Go(func() error {
			err := svc.Addresses.List(projectID, region).Pages(context.Background(), func(resp *computeapi.AddressList) error {
				for _, addr := range resp.Items {
					sendAddress(projectID, "compute.googleapis.com/Address", region, addr, out)
				}
				return nil
			})
			if err != nil {
				if gcperrors.ShouldSkip(err) {
					slog.Debug("skipping addresses in region", "project", projectID, "region", region, "reason", err)
					return nil
				}
				return fmt.Errorf("listing addresses in region %s: %w", region, err)
			}
			return nil
		})
	}

	return g.Wait()
}

func (l *AddressLister) ListByResourceID(input ResourceIDInput, out *pipeline.P[output.GCPResource]) error {
	svc, err := computeapi.NewService(context.Background(), l.clientOptions...)
	if err != nil {
		return fmt.Errorf("creating compute client: %w", err)
	}

	name, ok := pathSegment(input.ResourceID, "addresses")
	if !ok {
		return newResourceIDError(input.ResourceType, input.ResourceID, "a full path containing addresses/{name}")
	}

	if input.ResourceType == "compute.googleapis.com/GlobalAddress" {
		addr, err := svc.GlobalAddresses.Get(input.ProjectID, name).Do()
		if err != nil {
			if gcperrors.ShouldSkip(err) {
				slog.Debug("skipping global address", "project", input.ProjectID, "name", name, "reason", err)
				return nil
			}
			return fmt.Errorf("getting global address %s: %w", name, err)
		}
		sendAddress(input.ProjectID, input.ResourceType, "global", addr, out)
		return nil
	}

	region, ok := pathSegment(input.ResourceID, "regions")
	if !ok {
		return newResourceIDError(input.ResourceType, input.ResourceID, "a full path containing regions/{region}/addresses/{name}")
	}
	addr, err := svc.Addresses.Get(input.ProjectID, region, name).Do()
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping address", "project", input.ProjectID, "region", region, "name", name, "reason", err)
			return nil
		}
		return fmt.Errorf("getting address %s in region %s: %w", name, region, err)
	}
	sendAddress(input.ProjectID, input.ResourceType, region, addr, out)
	return nil
}

func (l *AddressLister) ResourceTypes() []string {
	return []string{"compute.googleapis.com/Address", "compute.googleapis.com/GlobalAddress"}
}

func sendAddress(projectID, resourceType, location string, addr *computeapi.Address, out *pipeline.P[output.GCPResource]) {
	resourceID := relativeGCPResourceID(addr.SelfLink)
	if resourceID == "" {
		resourceID = addressResourceID(projectID, location, addr.Name)
	}
	r := output.NewGCPResource(projectID, resourceType, resourceID)
	r.DisplayName = addr.Name
	r.Location = location
	r.Labels = addr.Labels
	if addr.Address != "" {
		r.IPs = []string{addr.Address}
	}
	r.Properties = map[string]any{
		"id":          fmt.Sprintf("%d", addr.Id),
		"status":      addr.Status,
		"addressType": addr.AddressType,
		"purpose":     addr.Purpose,
	}
	out.Send(r)
}

func addressResourceID(projectID, location, name string) string {
	if location == "global" {
		return fmt.Sprintf("projects/%s/global/addresses/%s", projectID, name)
	}
	return fmt.Sprintf("projects/%s/regions/%s/addresses/%s", projectID, location, name)
}
