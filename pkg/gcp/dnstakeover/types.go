package dnstakeover

import (
	"encoding/json"
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/output"
)

// DNSRecord represents a single DNS record from a Cloud DNS managed zone.
type DNSRecord struct {
	ProjectID  string
	ZoneName   string
	DNSName    string
	RecordName string
	Type       string   // "CNAME", "A", "AAAA", "NS"
	Values     []string // CNAME targets, IPs, or nameservers
}

// newTakeoverRisk builds an AurelianRisk for a subdomain takeover finding.
func newTakeoverRisk(name string, severity output.RiskSeverity, rec DNSRecord, extra map[string]any) output.AurelianRisk {
	ctx := map[string]any{
		"project_id":   rec.ProjectID,
		"zone_name":    rec.ZoneName,
		"dns_name":     rec.DNSName,
		"record_name":  rec.RecordName,
		"record_type":  rec.Type,
		"record_values": rec.Values,
	}
	for k, v := range extra {
		ctx[k] = v
	}

	ctxBytes, _ := json.Marshal(ctx)

	resourceID := fmt.Sprintf("projects/%s/managedZones/%s/rrsets/%s/%s",
		rec.ProjectID, rec.ZoneName, rec.RecordName, rec.Type)

	return output.AurelianRisk{
		Name:               name,
		Severity:           severity,
		ImpactedResourceID: resourceID,
		DeduplicationID:    fmt.Sprintf("%s:%s:%s:%s", name, rec.ProjectID, rec.ZoneName, rec.RecordName),
		Context:            ctxBytes,
	}
}
