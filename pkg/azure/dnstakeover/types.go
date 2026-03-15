package dnstakeover

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// AzureDNSRecord represents a single DNS record from an Azure DNS zone.
type AzureDNSRecord struct {
	SubscriptionID string
	ResourceGroup  string
	ZoneName       string
	RecordName     string
	FQDN           string
	Type           string   // "CNAME", "A", "AAAA", "NS"
	Values         []string // CNAME targets, IPs, or nameservers
	TTL            int64
}

// CheckContext holds shared state for checker functions.
type CheckContext struct {
	Ctx            context.Context
	Opts           plugin.AzureCommonRecon
	Credential     azcore.TokenCredential
	SubscriptionID string
	PublicIPCache  *publicIPCache
}

// publicIPCache holds lazily-initialized public IP state scoped to a single checker run.
type publicIPCache struct {
	once      sync.Once
	allocated map[string]bool // IP → allocated in our subscriptions
	err       error
}

// NewTakeoverRisk builds an AurelianRisk for an Azure subdomain takeover finding.
func NewTakeoverRisk(name string, severity output.RiskSeverity, rec AzureDNSRecord, extra map[string]any) output.AurelianRisk {
	merged := maps.Clone(extra)
	merged["subscription_id"] = rec.SubscriptionID
	merged["resource_group"] = rec.ResourceGroup
	merged["zone_name"] = rec.ZoneName
	merged["record_name"] = rec.RecordName
	merged["fqdn"] = rec.FQDN
	merged["record_type"] = rec.Type
	merged["record_values"] = rec.Values

	ctxBytes, _ := json.Marshal(merged)

	resourceID := fmt.Sprintf(
		"/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/dnsZones/%s/%s/%s",
		rec.SubscriptionID, rec.ResourceGroup, rec.ZoneName, rec.Type, rec.RecordName,
	)

	return output.AurelianRisk{
		Name:               name,
		Severity:           severity,
		ImpactedResourceID: resourceID,
		DeduplicationID:    fmt.Sprintf("%s:%s:%s:%s", name, rec.SubscriptionID, rec.ZoneName, rec.RecordName),
		Context:            ctxBytes,
	}
}

func ptrTo[T any](v T) *T { return &v }
