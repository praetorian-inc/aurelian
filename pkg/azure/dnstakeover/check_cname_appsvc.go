package dnstakeover

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("CNAME", "appsvc-takeover", checkAppService)
}

const appServiceSuffix = ".azurewebsites.net"

func checkAppService(ctx CheckContext, rec AzureDNSRecord, out *pipeline.P[model.AurelianModel]) error {
	for _, val := range rec.Values {
		if !strings.HasSuffix(strings.ToLower(val), appServiceSuffix) {
			continue
		}

		appName, _ := strings.CutSuffix(strings.ToLower(val), appServiceSuffix)
		if appName == "" {
			continue
		}

		available, err := checkWebAppNameAvailability(ctx, appName)
		if err != nil {
			slog.Warn("app service name check failed",
				"record", rec.RecordName, "app", appName, "error", err)
			continue
		}

		if !available {
			continue
		}

		out.Send(NewTakeoverRisk(
			"appsvc-subdomain-takeover",
			output.RiskSeverityHigh,
			rec,
			map[string]any{
				"service":      "App Service",
				"cname_target": val,
				"app_name":     appName,
				"description": fmt.Sprintf(
					"CNAME %q points to %s which is available for registration. "+
						"An attacker can create an App Service with this name and serve arbitrary content.",
					rec.FQDN, val,
				),
				"remediation": "Remove the stale CNAME record or recreate the App Service. " +
					"Add a domain verification TXT record (asuid.<subdomain>) to prevent future hijacking.",
				"references": []string{
					"https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover",
				},
			},
		))
	}
	return nil
}

func checkWebAppNameAvailability(ctx CheckContext, appName string) (bool, error) {
	client, err := armappservice.NewWebSiteManagementClient(ctx.SubscriptionID, ctx.Credential, nil)
	if err != nil {
		return false, fmt.Errorf("create app service client: %w", err)
	}

	resp, err := client.CheckNameAvailability(context.Background(), armappservice.ResourceNameAvailabilityRequest{
		Name: &appName,
		Type: ptrTo(armappservice.CheckNameResourceTypesMicrosoftWebSites),
	}, nil)
	if err != nil {
		return false, fmt.Errorf("check name availability: %w", err)
	}

	if resp.NameAvailable == nil {
		return false, nil
	}
	return *resp.NameAvailable, nil
}
