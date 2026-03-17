package dnstakeover

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/trafficmanager/armtrafficmanager"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("CNAME", "trafficmgr-takeover", checkTrafficManager)
}

const trafficManagerSuffix = ".trafficmanager.net"

func checkTrafficManager(ctx CheckContext, rec AzureDNSRecord, out *pipeline.P[model.AurelianModel]) error {
	for _, val := range rec.Values {
		if !strings.HasSuffix(strings.ToLower(val), trafficManagerSuffix) {
			continue
		}

		profileName, _ := strings.CutSuffix(strings.ToLower(val), trafficManagerSuffix)
		if profileName == "" {
			continue
		}

		available, err := checkTrafficManagerDNSAvailability(ctx, profileName)
		if err != nil {
			slog.Warn("traffic manager dns check failed",
				"record", rec.RecordName, "profile", profileName, "error", err)
			continue
		}

		if !available {
			continue
		}

		out.Send(NewTakeoverRisk(
			"trafficmgr-subdomain-takeover",
			output.RiskSeverityHigh,
			rec,
			map[string]any{
				"service":      "Traffic Manager",
				"cname_target": val,
				"profile_name": profileName,
				"description": fmt.Sprintf(
					"CNAME %q points to %s which is available for registration. "+
						"An attacker can create a Traffic Manager profile with this DNS name and route all traffic. "+
						"Note: profiles with no endpoints also return NXDOMAIN — verify this is not a misconfigured but existing profile.",
					rec.FQDN, val,
				),
				"remediation": "Remove the stale CNAME record or recreate the Traffic Manager profile.",
				"references": []string{
					"https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover",
				},
			},
		))
	}
	return nil
}

func checkTrafficManagerDNSAvailability(ctx CheckContext, profileName string) (bool, error) {
	client, err := armtrafficmanager.NewProfilesClient(ctx.SubscriptionID, ctx.Credential, nil)
	if err != nil {
		return false, fmt.Errorf("create traffic manager client: %w", err)
	}

	resp, err := client.CheckTrafficManagerRelativeDNSNameAvailability(
		context.Background(),
		armtrafficmanager.CheckTrafficManagerRelativeDNSNameAvailabilityParameters{
			Name: &profileName,
			Type: ptrTo("Microsoft.Network/trafficManagerProfiles"),
		},
		nil,
	)
	if err != nil {
		return false, fmt.Errorf("check dns availability: %w", err)
	}

	if resp.NameAvailable == nil {
		return false, nil
	}
	return *resp.NameAvailable, nil
}
