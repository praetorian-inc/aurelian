package extraction

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("microsoft.web/sites", "webapp-settings", extractWebAppSettings)
	mustRegister("microsoft.web/sites", "webapp-connections", extractWebAppConnections)
	mustRegister("microsoft.web/sites", "webapp-hostkeys", extractWebAppHostKeys)
}

func extractWebAppSettings(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	resourceGroup, appName, err := parseWebAppID(r.ResourceID)
	if err != nil {
		return err
	}

	client, err := armappservice.NewWebAppsClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create web apps client: %w", err)
	}

	settings, err := client.ListApplicationSettings(ctx.Context, resourceGroup, appName, nil)
	if err != nil {
		slog.Warn("failed to list app settings", "app", appName, "error", err)
		return nil
	}

	if len(settings.Properties) > 0 {
		if data, err := json.Marshal(settings.Properties); err == nil {
			out.Send(output.ScanInputFromAzureResource(r, "WebApp AppSettings", data))
		}
	}
	return nil
}

func extractWebAppConnections(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	resourceGroup, appName, err := parseWebAppID(r.ResourceID)
	if err != nil {
		return err
	}

	client, err := armappservice.NewWebAppsClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create web apps client: %w", err)
	}

	connStrings, err := client.ListConnectionStrings(ctx.Context, resourceGroup, appName, nil)
	if err != nil {
		slog.Warn("failed to list connection strings", "app", appName, "error", err)
		return nil
	}

	if connStrings.Properties != nil {
		if data, err := json.Marshal(connStrings.Properties); err == nil {
			out.Send(output.ScanInputFromAzureResource(r, "WebApp ConnectionStrings", data))
		}
	}
	return nil
}

func extractWebAppHostKeys(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	resourceGroup, appName, err := parseWebAppID(r.ResourceID)
	if err != nil {
		return err
	}

	client, err := armappservice.NewWebAppsClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create web apps client: %w", err)
	}

	hostKeys, err := client.ListHostKeys(ctx.Context, resourceGroup, appName, nil)
	if err != nil {
		slog.Warn("failed to list host keys", "app", appName, "error", err)
		return nil
	}

	if data, err := json.Marshal(hostKeys); err == nil && len(data) > 2 {
		out.Send(output.ScanInputFromAzureResource(r, "WebApp HostKeys", data))
	}
	return nil
}

func parseWebAppID(resourceID string) (resourceGroup, appName string, err error) {
	_, rg, segments, parseErr := parseAzureResourceID(resourceID)
	if parseErr != nil {
		return "", "", fmt.Errorf("failed to parse web app resource ID: %w", parseErr)
	}
	appName = segments["sites"]
	if appName == "" {
		return "", "", fmt.Errorf("no 'sites' segment in resource ID %s", resourceID)
	}
	return rg, appName, nil
}
