package dnstakeover

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/gcp/gcperrors"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"google.golang.org/api/dns/v1"
)

// errZoneFound stops managedZones.list pagination once the delegated zone has
// been matched. It never escapes delegatedZoneExists.
var errZoneFound = errors.New("delegated zone found")

func (c *Checker) checkNS(rec DNSRecord, out *pipeline.P[model.AurelianModel]) {
	// An NS record set at the apex of its own zone is that zone's own
	// delegation, not a delegation to a child zone.
	if rec.RecordName == strings.TrimSuffix(rec.DNSName, ".") {
		slog.Debug("skipping apex NS record set", "domain", rec.RecordName)
		return
	}

	for _, ns := range rec.Values {
		ns = strings.TrimSuffix(ns, ".")

		// Only check Google Cloud DNS nameservers
		if !strings.Contains(ns, "ns-cloud-") || !strings.Contains(ns, ".googledomains.com") {
			continue
		}

		if c.delegatedZoneExists(rec.ProjectID, rec.RecordName) {
			continue
		}

		slog.Debug("dangling NS delegation detected",
			"domain", rec.RecordName, "nameserver", ns)

		out.Send(newTakeoverRisk(
			"GCP Subdomain Takeover: Dangling NS Delegation",
			output.RiskSeverityCritical,
			rec,
			map[string]any{
				"service":     "Cloud DNS",
				"nameserver":  ns,
				"description": fmt.Sprintf("NS record delegates to Cloud DNS nameserver but delegated zone may not exist: %s", ns),
				"remediation": "Delete the NS delegation or create the corresponding Cloud DNS zone",
			},
		))
		break // one finding per record is sufficient
	}
}

// delegatedZoneExists reports whether any project in scope owns a Cloud DNS
// zone for subdomain. A delegated child zone is frequently created in a
// different project than the parent zone holding the NS record, so every
// resolved project is consulted, not just recordProjectID.
func (c *Checker) delegatedZoneExists(recordProjectID, subdomain string) bool {
	normalized := strings.TrimSuffix(subdomain, ".")

	for _, projectID := range c.candidateProjects(recordProjectID) {
		owns, err := c.projectOwnsZone(projectID, normalized)
		if err != nil {
			if gcperrors.ShouldSkip(err) {
				// Disabled API or permission denied: this project cannot be
				// shown to own the zone, so it is simply not an owner.
				slog.Debug("skipping dns zone ownership lookup",
					"project", projectID, "zone", normalized, "reason", err)
				continue
			}
			// Any other error is inconclusive. Suppress the risk rather than
			// report a delegation as dangling on incomplete evidence.
			slog.Warn("dns zone ownership lookup failed; assuming zone exists",
				"project", projectID, "zone", normalized, "error", err)
			return true
		}
		if owns {
			return true
		}
	}
	return false
}

// candidateProjects returns the projects to consult for zone ownership: every
// project resolved for the scan, plus the record's own project. The record's
// project is always included so the check never covers less than it did when it
// consulted that project alone.
func (c *Checker) candidateProjects(recordProjectID string) []string {
	projects := slices.Clone(c.projectIDs)
	if recordProjectID != "" && !slices.Contains(projects, recordProjectID) {
		projects = append(projects, recordProjectID)
	}
	return projects
}

// projectOwnsZone reports whether projectID holds a managed zone whose DnsName
// is exactly normalized. Matching is exact: a zone above or below the delegated
// name is a different zone and is not evidence that the delegation resolves.
func (c *Checker) projectOwnsZone(projectID, normalized string) (bool, error) {
	found := false
	err := c.dnsSvc.ManagedZones.List(projectID).Pages(context.Background(), func(resp *dns.ManagedZonesListResponse) error {
		for _, zone := range resp.ManagedZones {
			if strings.TrimSuffix(zone.DnsName, ".") == normalized {
				found = true
				return errZoneFound
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, errZoneFound) {
		return false, fmt.Errorf("listing dns zones in project %s: %w", projectID, err)
	}
	return found, nil
}
