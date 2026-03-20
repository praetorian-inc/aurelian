package dnstakeover

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func (c *Checker) checkNS(rec DNSRecord, out *pipeline.P[model.AurelianModel]) {
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

func (c *Checker) delegatedZoneExists(projectID, subdomain string) bool {
	resp, err := c.dnsSvc.ManagedZones.List(projectID).Context(context.Background()).Do()
	if err != nil {
		return true // API error — assume exists
	}

	normalized := strings.TrimSuffix(subdomain, ".")
	for _, zone := range resp.ManagedZones {
		zoneDNS := strings.TrimSuffix(zone.DnsName, ".")
		if zoneDNS == normalized || strings.HasSuffix(zoneDNS, "."+normalized) {
			return true
		}
	}
	return false
}
