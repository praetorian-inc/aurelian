package dnstakeover

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"sync"

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

// eipCache holds lazily-initialized EIP state scoped to a single checker run.
type eipCache struct {
	once         sync.Once
	ranges       []parsedPrefix
	allocatedIPs map[string]bool
	err          error
}

type parsedPrefix struct {
	network *net.IPNet
	region  string
	service string
}

// CheckContext holds shared state for checker functions.
type CheckContext struct {
	Ctx       context.Context
	Opts      plugin.AWSCommonRecon
	AccountID string
	EIPCache  *eipCache
}

// NewTakeoverRisk builds an AurelianRisk for a subdomain takeover finding.
func NewTakeoverRisk(name string, severity output.RiskSeverity, rec Route53Record, accountID string, extra map[string]any) output.AurelianRisk {
	merged := maps.Clone(extra)
	merged["account_id"] = accountID
	merged["zone_id"] = rec.ZoneID
	merged["zone_name"] = rec.ZoneName
	merged["record_name"] = rec.RecordName
	merged["record_type"] = rec.Type
	merged["record_values"] = rec.Values

	ctxBytes, _ := json.Marshal(merged)

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
