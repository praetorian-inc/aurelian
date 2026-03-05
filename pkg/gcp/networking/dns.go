package networking

import (
	"fmt"
	"log/slog"

	"google.golang.org/api/option"
	dnsapi "google.golang.org/api/dns/v1"

	"github.com/praetorian-inc/aurelian/pkg/gcp/gcperrors"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// DNSZoneLister enumerates Cloud DNS managed zones in a GCP project.
type DNSZoneLister struct {
	clientOptions []option.ClientOption
}

// NewDNSZoneLister creates a DNSZoneLister with the given client options.
func NewDNSZoneLister(clientOptions []option.ClientOption) *DNSZoneLister {
	return &DNSZoneLister{clientOptions: clientOptions}
}

// List enumerates all Cloud DNS managed zones for the given project.
func (l *DNSZoneLister) List(projectID string, out *pipeline.P[output.GCPResource]) error {
	svc, err := dnsapi.NewService(nil, l.clientOptions...)
	if err != nil {
		return fmt.Errorf("creating dns client: %w", err)
	}

	call := svc.ManagedZones.List(projectID)
	err = call.Pages(nil, func(resp *dnsapi.ManagedZonesListResponse) error {
		for _, zone := range resp.ManagedZones {
			r := output.NewGCPResource(projectID, "dns.googleapis.com/ManagedZone", zone.Name)
			r.DisplayName = zone.Name
			r.Properties = map[string]any{
				"dnsName":     zone.DnsName,
				"visibility":  zone.Visibility,
				"description": zone.Description,
			}
			out.Send(r)
		}
		return nil
	})
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping dns zones", "project", projectID, "reason", err)
			return nil
		}
		return fmt.Errorf("listing dns zones: %w", err)
	}
	return nil
}
