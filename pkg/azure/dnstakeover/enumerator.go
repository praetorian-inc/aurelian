package dnstakeover

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// DNSEnumerator lists all DNS records from Azure DNS zones across subscriptions.
type DNSEnumerator struct {
	credential azcore.TokenCredential
}

// NewDNSEnumerator creates a DNS record enumerator.
func NewDNSEnumerator(credential azcore.TokenCredential) *DNSEnumerator {
	return &DNSEnumerator{credential: credential}
}

// EnumerateSubscription lists all records from all DNS zones in the given subscription.
// Pipeline signature: string (subscriptionID) -> AzureDNSRecord.
func (e *DNSEnumerator) EnumerateSubscription(subscriptionID string, out *pipeline.P[AzureDNSRecord]) error {
	client, err := armdns.NewZonesClient(subscriptionID, e.credential, nil)
	if err != nil {
		return fmt.Errorf("creating dns zones client: %w", err)
	}

	recordClient, err := armdns.NewRecordSetsClient(subscriptionID, e.credential, nil)
	if err != nil {
		return fmt.Errorf("creating dns record sets client: %w", err)
	}

	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			slog.Warn("failed to list dns zones", "subscription", subscriptionID, "error", err)
			return nil
		}

		for _, zone := range page.Value {
			if zone.Name == nil || zone.ID == nil {
				continue
			}
			rg := extractResourceGroup(*zone.ID)
			if err := e.enumerateZoneRecords(recordClient, subscriptionID, rg, *zone.Name, out); err != nil {
				slog.Warn("failed to enumerate zone records",
					"subscription", subscriptionID, "zone", *zone.Name, "error", err)
			}
		}
	}
	return nil
}

func (e *DNSEnumerator) enumerateZoneRecords(
	client *armdns.RecordSetsClient,
	subscriptionID, resourceGroup, zoneName string,
	out *pipeline.P[AzureDNSRecord],
) error {
	pager := client.NewListByDNSZonePager(resourceGroup, zoneName, nil)
	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			return fmt.Errorf("listing records for zone %s: %w", zoneName, err)
		}

		for _, rs := range page.Value {
			if rs.Name == nil || rs.Type == nil {
				continue
			}

			rec, ok := toAzureDNSRecord(subscriptionID, resourceGroup, zoneName, rs)
			if !ok {
				continue
			}
			out.Send(rec)
		}
	}
	return nil
}

func toAzureDNSRecord(subscriptionID, resourceGroup, zoneName string, rs *armdns.RecordSet) (AzureDNSRecord, bool) {
	name := *rs.Name
	recordType := extractRecordType(*rs.Type)

	var fqdn string
	if rs.Properties != nil && rs.Properties.Fqdn != nil {
		fqdn = strings.TrimSuffix(*rs.Properties.Fqdn, ".")
	}

	var ttl int64
	if rs.Properties != nil && rs.Properties.TTL != nil {
		ttl = *rs.Properties.TTL
	}

	var values []string

	switch recordType {
	case "CNAME":
		if rs.Properties == nil || rs.Properties.CnameRecord == nil || rs.Properties.CnameRecord.Cname == nil {
			return AzureDNSRecord{}, false
		}
		values = []string{strings.TrimSuffix(*rs.Properties.CnameRecord.Cname, ".")}

	case "A":
		if rs.Properties == nil || rs.Properties.ARecords == nil {
			return AzureDNSRecord{}, false
		}
		for _, a := range rs.Properties.ARecords {
			if a.IPv4Address != nil {
				values = append(values, *a.IPv4Address)
			}
		}

	case "AAAA":
		if rs.Properties == nil || rs.Properties.AaaaRecords == nil {
			return AzureDNSRecord{}, false
		}
		for _, a := range rs.Properties.AaaaRecords {
			if a.IPv6Address != nil {
				values = append(values, *a.IPv6Address)
			}
		}

	case "NS":
		if name == "@" {
			return AzureDNSRecord{}, false
		}
		if rs.Properties == nil || rs.Properties.NsRecords == nil {
			return AzureDNSRecord{}, false
		}
		for _, ns := range rs.Properties.NsRecords {
			if ns.Nsdname != nil {
				values = append(values, strings.TrimSuffix(*ns.Nsdname, "."))
			}
		}

	default:
		return AzureDNSRecord{}, false
	}

	if len(values) == 0 {
		return AzureDNSRecord{}, false
	}

	return AzureDNSRecord{
		SubscriptionID: subscriptionID,
		ResourceGroup:  resourceGroup,
		ZoneName:       zoneName,
		RecordName:     name,
		FQDN:           fqdn,
		Type:           recordType,
		Values:         values,
		TTL:            ttl,
	}, true
}

// extractRecordType extracts "CNAME" from "Microsoft.Network/dnszones/CNAME".
func extractRecordType(fullType string) string {
	_, after, found := strings.Cut(fullType, "dnszones/")
	if found {
		return after
	}
	parts := strings.Split(fullType, "/")
	return parts[len(parts)-1]
}

// extractResourceGroup extracts the resource group from an Azure resource ID.
func extractResourceGroup(resourceID string) string {
	parts := strings.Split(resourceID, "/")
	for i, p := range parts {
		if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
