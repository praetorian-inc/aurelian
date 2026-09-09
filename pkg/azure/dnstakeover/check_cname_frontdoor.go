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
	mustRegister("CNAME", "frontdoor-takeover", checkFrontDoor)
}

const frontdoorSuffix = ".azurefd.net"

func checkFrontDoor(ctx CheckContext, rec AzureDNSRecord, out *pipeline.P[model.AurelianModel]) error {
	for _, val := range rec.Values {
		endpointName, ok := frontDoorEndpointName(val)
		if !ok {
			continue
		}

		available, err := checkFrontDoorNameAvailability(ctx, endpointName)
		if err != nil {
			slog.Warn("front door name check failed",
				"record", rec.RecordName, "endpoint", endpointName, "error", err)
			continue
		}

		if !available {
			continue
		}

		out.Send(NewTakeoverRisk(
			"frontdoor-subdomain-takeover",
			output.RiskSeverityHigh,
			rec,
			map[string]any{
				"service":       "Front Door",
				"cname_target":  val,
				"endpoint_name": endpointName,
				"description": fmt.Sprintf(
					"CNAME %q points to %s which is available for registration. "+
						"An attacker can create a Front Door endpoint with this name and serve arbitrary content.",
					rec.FQDN, val,
				),
				"remediation": "Remove the stale CNAME record or recreate the Front Door endpoint.",
				"references": []string{
					"https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover",
				},
			},
		))
	}
	return nil
}

func frontDoorEndpointName(val string) (string, bool) {
	v := strings.ToLower(strings.TrimSuffix(val, "."))
	name, ok := strings.CutSuffix(v, frontdoorSuffix)
	if !ok || name == "" || strings.Contains(name, ".") {
		return "", false
	}
	return name, true
}

func checkFrontDoorNameAvailability(ctx CheckContext, endpointName string) (bool, error) {
	client, err := armcdn.NewManagementClient(ctx.SubscriptionID, ctx.Credential, nil)
	if err != nil {
		return false, fmt.Errorf("create cdn client: %w", err)
	}

	resp, err := client.CheckNameAvailabilityWithSubscription(
		context.Background(),
		armcdn.CheckNameAvailabilityInput{
			Name: &endpointName,
			Type: ptrTo(armcdn.ResourceTypeMicrosoftCdnProfilesAfdEndpoints),
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
