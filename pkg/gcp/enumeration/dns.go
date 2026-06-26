package enumeration

import (
	"context"
	"fmt"
	"log/slog"

	dnsapi "google.golang.org/api/dns/v1"
	"google.golang.org/api/option"

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
	svc, err := dnsapi.NewService(context.Background(), l.clientOptions...)
	if err != nil {
		return fmt.Errorf("creating dns client: %w", err)
	}

	call := svc.ManagedZones.List(projectID)
	err = call.Pages(context.Background(), func(resp *dnsapi.ManagedZonesListResponse) error {
		for _, zone := range resp.ManagedZones {
			sendDNSZone(projectID, zone, out)
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

func (l *DNSZoneLister) ListByResourceID(input ResourceIDInput, out *pipeline.P[output.GCPResource]) error {
	svc, err := dnsapi.NewService(context.Background(), l.clientOptions...)
	if err != nil {
		return fmt.Errorf("creating dns client: %w", err)
	}
	zoneName := lastPathPart(input.ResourceID)
	zone, err := svc.ManagedZones.Get(input.ProjectID, zoneName).Do()
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping dns zone", "project", input.ProjectID, "zone", zoneName, "reason", err)
			return nil
		}
		return fmt.Errorf("getting dns zone %s: %w", zoneName, err)
	}
	sendDNSZone(input.ProjectID, zone, out)
	return nil
}

func (l *DNSZoneLister) ResourceTypes() []string { return []string{"dns.googleapis.com/ManagedZone"} }

func sendDNSZone(projectID string, zone *dnsapi.ManagedZone, out *pipeline.P[output.GCPResource]) {
	r := output.NewGCPResource(projectID, "dns.googleapis.com/ManagedZone", zone.Name)
	r.DisplayName = zone.Name
	r.Properties = map[string]any{
		"dnsName":     zone.DnsName,
		"visibility":  zone.Visibility,
		"description": zone.Description,
	}
	out.Send(r)
}
