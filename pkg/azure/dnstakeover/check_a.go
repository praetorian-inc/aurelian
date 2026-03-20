package dnstakeover

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("A", "orphaned-ip", checkOrphanedIP)
	mustRegister("AAAA", "orphaned-ip", checkOrphanedIP)
}

func checkOrphanedIP(ctx CheckContext, rec AzureDNSRecord, out *pipeline.P[model.AurelianModel]) error {
	ctx.PublicIPCache.once.Do(func() {
		ctx.PublicIPCache.allocated, ctx.PublicIPCache.err = fetchAllocatedPublicIPs(ctx)
	})
	if ctx.PublicIPCache.err != nil {
		slog.Warn("public ip cache initialization failed", "error", ctx.PublicIPCache.err)
		return nil
	}

	for _, ip := range rec.Values {
		if !isPublicIP(ip) {
			continue
		}

		if ctx.PublicIPCache.allocated[ip] {
			continue
		}

		out.Send(NewTakeoverRisk(
			"orphaned-ip-a-record",
			output.RiskSeverityLow,
			rec,
			map[string]any{
				"service":     "Public IP Address",
				"dangling_ip": ip,
				"description": fmt.Sprintf(
					"%s record %q points to %s which is not allocated as a public IP "+
						"in any accessible subscription. The IP may be reclaimable.",
					rec.Type, rec.FQDN, ip,
				),
				"remediation": "Remove the stale DNS record or re-allocate the public IP address.",
				"references": []string{
					"https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover",
				},
			},
		))
	}
	return nil
}

func isPublicIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return ip.IsGlobalUnicast() && !ip.IsPrivate()
}

func fetchAllocatedPublicIPs(ctx CheckContext) (map[string]bool, error) {
	allocated := make(map[string]bool)

	for _, subID := range ctx.SubscriptionIDs {
		client, err := armnetwork.NewPublicIPAddressesClient(subID, ctx.Credential, nil)
		if err != nil {
			slog.Warn("failed to create public ip client", "subscription", subID, "error", err)
			continue
		}

		pager := client.NewListAllPager(nil)
		for pager.More() {
			page, err := pager.NextPage(context.Background())
			if err != nil {
				slog.Warn("failed to list public ips", "subscription", subID, "error", err)
				break
			}

			for _, pip := range page.Value {
				if pip.Properties != nil && pip.Properties.IPAddress != nil {
					allocated[*pip.Properties.IPAddress] = true
				}
			}
		}
	}

	slog.Info("azure public ip cache initialized", "count", len(allocated))
	return allocated, nil
}
