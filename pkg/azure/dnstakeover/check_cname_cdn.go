package dnstakeover

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cdn/armcdn"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("CNAME", "cdn-takeover", checkCDN)
}

const cdnSuffix = ".azureedge.net"

func checkCDN(ctx CheckContext, rec AzureDNSRecord, out *pipeline.P[model.AurelianModel]) error {
	for _, val := range rec.Values {
		if !strings.HasSuffix(strings.ToLower(val), cdnSuffix) {
			continue
		}

		endpointName, _ := strings.CutSuffix(strings.ToLower(val), cdnSuffix)
		if endpointName == "" {
			continue
		}

		available, err := checkCDNNameAvailability(ctx, endpointName)
		if err != nil {
			slog.Warn("cdn name check failed",
				"record", rec.RecordName, "endpoint", endpointName, "error", err)
			continue
		}

		if !available {
			continue
		}

		out.Send(NewTakeoverRisk(
			"cdn-subdomain-takeover",
			output.RiskSeverityHigh,
			rec,
			map[string]any{
				"service":       "CDN (Classic)",
				"cname_target":  val,
				"endpoint_name": endpointName,
				"description": fmt.Sprintf(
					"CNAME %q points to %s which is available for registration. "+
						"An attacker can create a CDN endpoint with this name and serve arbitrary content.",
					rec.FQDN, val,
				),
				"remediation": "Remove the stale CNAME record or recreate the CDN endpoint.",
				"references": []string{
					"https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover",
				},
			},
		))
	}
	return nil
}

func checkCDNNameAvailability(ctx CheckContext, endpointName string) (bool, error) {
	client, err := armcdn.NewManagementClient(ctx.SubscriptionID, ctx.Credential, nil)
	if err != nil {
		return false, fmt.Errorf("create cdn client: %w", err)
	}

	resp, err := client.CheckNameAvailabilityWithSubscription(
		context.Background(),
		armcdn.CheckNameAvailabilityInput{
			Name: &endpointName,
			Type: ptrTo(armcdn.ResourceTypeMicrosoftCdnProfilesEndpoints),
		},
		nil,
	)
	if err != nil {
		return false, fmt.Errorf("check name availability: %w", err)
	}

	if resp.NameAvailable == nil {
		return false, nil
	}
	return *resp.NameAvailable, nil
}
