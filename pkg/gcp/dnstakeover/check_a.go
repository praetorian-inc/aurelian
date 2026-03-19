package dnstakeover

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func (c *Checker) checkA(rec DNSRecord, out *pipeline.P[model.AurelianModel]) {
	for _, ip := range rec.Values {
		if !isPublicIP(ip) || c.ipInUse(rec.ProjectID, ip) {
			continue
		}

		slog.Debug("orphaned IP detected", "domain", rec.RecordName, "ip", ip)

		out.Send(newTakeoverRisk(
			"GCP Subdomain Takeover: Orphaned IP Address",
			output.RiskSeverityLow,
			rec,
			map[string]any{
				"service":     "Compute Engine / Load Balancing",
				"ip":          ip,
				"description": fmt.Sprintf("A/AAAA record points to potentially orphaned IP address: %s", ip),
				"remediation": "Delete the DNS record or verify the IP address is properly allocated",
			},
		))
	}
}

func isPublicIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return ip.IsGlobalUnicast() && !ip.IsPrivate()
}

func (c *Checker) ipInUse(projectID, ipAddress string) bool {
	resp, err := c.computeSvc.Addresses.AggregatedList(projectID).Do()
	if err != nil {
		return true // API error — assume in use to avoid false positive
	}
	for _, list := range resp.Items {
		for _, addr := range list.Addresses {
			if addr.Address == ipAddress {
				return addr.Status == "IN_USE"
			}
		}
	}
	return false
}
