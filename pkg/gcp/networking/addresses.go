package networking

import (
	"fmt"
	"log/slog"
	"sync"

	"google.golang.org/api/option"
	computeapi "google.golang.org/api/compute/v1"

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
	svc, err := computeapi.NewService(nil, l.clientOptions...)
	if err != nil {
		return fmt.Errorf("creating compute client: %w", err)
	}

	// Global addresses.
	err = svc.GlobalAddresses.List(projectID).Pages(nil, func(resp *computeapi.AddressList) error {
		for _, addr := range resp.Items {
			r := output.NewGCPResource(projectID, "compute.googleapis.com/GlobalAddress", fmt.Sprintf("%d", addr.Id))
			r.DisplayName = addr.Name
			r.Location = "global"
			r.Labels = addr.Labels
			if addr.Address != "" {
				r.IPs = []string{addr.Address}
			}
			r.Properties = map[string]any{
				"status":      addr.Status,
				"addressType": addr.AddressType,
				"purpose":     addr.Purpose,
			}
			out.Send(r)
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
	err = svc.Regions.List(projectID).Pages(nil, func(resp *computeapi.RegionList) error {
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

	// Fan out per region.
	var (
		wg       sync.WaitGroup
		sem      = make(chan struct{}, 10)
		mu       sync.Mutex
		firstErr error
	)

	for _, region := range regions {
		wg.Add(1)
		sem <- struct{}{}
		go func(region string) {
			defer wg.Done()
			defer func() { <-sem }()

			err := svc.Addresses.List(projectID, region).Pages(nil, func(resp *computeapi.AddressList) error {
				for _, addr := range resp.Items {
					r := output.NewGCPResource(projectID, "compute.googleapis.com/Address", fmt.Sprintf("%d", addr.Id))
					r.DisplayName = addr.Name
					r.Location = region
					r.Labels = addr.Labels
					if addr.Address != "" {
						r.IPs = []string{addr.Address}
					}
					r.Properties = map[string]any{
						"status":      addr.Status,
						"addressType": addr.AddressType,
						"purpose":     addr.Purpose,
					}
					out.Send(r)
				}
				return nil
			})
			if err != nil {
				if gcperrors.ShouldSkip(err) {
					slog.Debug("skipping addresses in region", "project", projectID, "region", region, "reason", err)
					return
				}
				mu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("listing addresses in region %s: %w", region, err)
				}
				mu.Unlock()
			}
		}(region)
	}

	wg.Wait()
	return firstErr
}
