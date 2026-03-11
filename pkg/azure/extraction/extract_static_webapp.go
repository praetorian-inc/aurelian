package extraction

import (
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("microsoft.web/staticsites", "static-webapp-settings", extractStaticWebAppSettings)
}

func extractStaticWebAppSettings(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	rg, siteName, err := parseStaticWebAppID(r.ResourceID)
	if err != nil {
		return err
	}

	client, err := armappservice.NewStaticSitesClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create static sites client: %w", err)
	}

	settings, err := client.ListStaticSiteAppSettings(ctx.Context, rg, siteName, nil)
	if err != nil {
		return handleExtractError(err, "static-webapp-settings", r.ResourceID)
	}

	if len(settings.Properties) > 0 {
		if data, merr := json.Marshal(settings.Properties); merr == nil {
			out.Send(output.ScanInputFromAzureResource(r, "StaticWebApp AppSettings", data))
		}
	}
	return nil
}

func parseStaticWebAppID(resourceID string) (resourceGroup, siteName string, err error) {
	_, rg, segments, parseErr := parseAzureResourceID(resourceID)
	if parseErr != nil {
		return "", "", fmt.Errorf("failed to parse static web app resource ID: %w", parseErr)
	}
	siteName = segments["staticSites"]
	if siteName == "" {
		return "", "", fmt.Errorf("no 'staticSites' segment in resource ID %s", resourceID)
	}
	return rg, siteName, nil
}
