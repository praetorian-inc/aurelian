package dnstakeover

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/gcp/gcperrors"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/option"
)

// ManagedZoneInput identifies a single Cloud DNS managed zone to enumerate.
type ManagedZoneInput struct {
	ProjectID  string
	ResourceID string
}

// DNSEnumerator lists all DNS records from Cloud DNS managed zones in a project.
type DNSEnumerator struct {
	clientOptions []option.ClientOption
}

// NewDNSEnumerator creates a DNS record enumerator.
func NewDNSEnumerator(clientOptions []option.ClientOption) *DNSEnumerator {
	return &DNSEnumerator{clientOptions: clientOptions}
}

// EnumerateProject lists all records from all managed zones in the given project.
// Pipeline signature: string (projectID) -> DNSRecord.
func (e *DNSEnumerator) EnumerateProject(projectID string, out *pipeline.P[DNSRecord]) error {
	svc, err := dns.NewService(context.Background(), e.clientOptions...)
	if err != nil {
		return fmt.Errorf("creating dns client: %w", err)
	}

	err = svc.ManagedZones.List(projectID).Pages(context.Background(), func(resp *dns.ManagedZonesListResponse) error {
		for _, zone := range resp.ManagedZones {
			if err := e.enumerateZoneRecords(svc, projectID, zone, out); err != nil {
				slog.Warn("failed to enumerate zone records",
					"project", projectID, "zone", zone.Name, "error", err)
			}
		}
		return nil
	})
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping dns enumeration", "project", projectID, "reason", err)
			return nil
		}
		return fmt.Errorf("listing dns zones: %w", err)
	}
	return nil
}

// EnumerateManagedZone lists all relevant records from a single Cloud DNS managed zone.
func (e *DNSEnumerator) EnumerateManagedZone(input ManagedZoneInput, out *pipeline.P[DNSRecord]) error {
	svc, err := dns.NewService(context.Background(), e.clientOptions...)
	if err != nil {
		return fmt.Errorf("creating dns client: %w", err)
	}

	zoneName := managedZoneName(input.ResourceID)
	zone, err := svc.ManagedZones.Get(input.ProjectID, zoneName).Do()
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping dns managed zone", "project", input.ProjectID, "zone", zoneName, "reason", err)
			return nil
		}
		return fmt.Errorf("getting dns managed zone %s: %w", zoneName, err)
	}
	return e.enumerateZoneRecords(svc, input.ProjectID, zone, out)
}

func managedZoneName(resourceID string) string {
	parts := strings.Split(strings.Trim(resourceID, "/"), "/")
	if len(parts) == 0 {
		return resourceID
	}
	return parts[len(parts)-1]
}

func (e *DNSEnumerator) enumerateZoneRecords(svc *dns.Service, projectID string, zone *dns.ManagedZone, out *pipeline.P[DNSRecord]) error {
	return svc.ResourceRecordSets.List(projectID, zone.Name).Pages(context.Background(), func(resp *dns.ResourceRecordSetsListResponse) error {
		for _, rrset := range resp.Rrsets {
			switch rrset.Type {
			case "CNAME", "A", "AAAA":
				out.Send(DNSRecord{
					ProjectID:  projectID,
					ZoneName:   zone.Name,
					DNSName:    zone.DnsName,
					RecordName: strings.TrimSuffix(rrset.Name, "."),
					Type:       rrset.Type,
					Values:     rrset.Rrdatas,
				})
			case "NS":
				// Only emit NS delegations, not the zone apex NS records
				if rrset.Name != zone.DnsName {
					out.Send(DNSRecord{
						ProjectID:  projectID,
						ZoneName:   zone.Name,
						DNSName:    zone.DnsName,
						RecordName: strings.TrimSuffix(rrset.Name, "."),
						Type:       rrset.Type,
						Values:     rrset.Rrdatas,
					})
				}
			}
		}
		return nil
	})
}
