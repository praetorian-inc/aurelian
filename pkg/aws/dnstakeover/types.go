package dnstakeover

import (
	"encoding/json"
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// Route53Record represents a single DNS record from a public hosted zone.
type Route53Record struct {
	ZoneID     string
	ZoneName   string
	RecordName string
	Type       string   // "CNAME", "A", "NS", etc.
	Values     []string // CNAME targets, IPs, or nameservers
	IsAlias    bool
}

// CheckContext holds shared state for checker functions.
type CheckContext struct {
	Opts      plugin.AWSCommonRecon
	AccountID string
}

// NewTakeoverRisk builds an AurelianRisk for a subdomain takeover finding.
func NewTakeoverRisk(name string, severity output.RiskSeverity, rec Route53Record, accountID string, context map[string]any) output.AurelianRisk {
	context["account_id"] = accountID
	context["zone_id"] = rec.ZoneID
	context["zone_name"] = rec.ZoneName
	context["record_name"] = rec.RecordName
	context["record_type"] = rec.Type
	context["record_values"] = rec.Values

	ctxBytes, _ := json.Marshal(context)

	resourceID := fmt.Sprintf("arn:aws:route53:::hostedzone/%s/recordset/%s/%s",
		rec.ZoneID, rec.RecordName, rec.Type)

	return output.AurelianRisk{
		Name:               name,
		Severity:           severity,
		ImpactedResourceID: resourceID,
		DeduplicationID:    fmt.Sprintf("%s:%s:%s", name, rec.ZoneID, rec.RecordName),
		Context:            ctxBytes,
	}
}
